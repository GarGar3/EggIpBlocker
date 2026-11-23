import datetime
import ipaddress
import os
import re
import subprocess
import threading
import time
import pyodbc

# ==========================================
# CONFIGURATION
# ==========================================
SQL_CONFIG = {
    "driver": "{ODBC Driver 17 for SQL Server}",
    "server": "localhost",  # Or 'SERVER_NAME\INSTANCE_NAME'
    "database": "master",
    "trusted_connection": (
        "yes"  # Uses Windows Auth; set to 'no' if using SQL Auth below
    ),
    "uid": "",
    "pwd": "",
}

# Array of usernames to EXEMPT from blocking (case-insensitive).
# ANY username NOT in this list will trigger an IP block!
EXEMPT_USERS = [
    "admin_user",
    "backup_service",
    "app_readonly",
]

# Array of IPs to NEVER block (Crucial: add your own admin/office IPs here!)
EXEMPT_IPS = {"127.0.0.1", "::1", "<local machine>"}

# File paths for persistent tracking and logging
BLOCKED_LOG_FILE = "blocked_ips_log.txt"
BLOCKED_HISTORY_FILE = "blocked_ips_history.txt"
CHECK_INTERVAL_SECONDS = 60

# ==========================================
# GLOBAL STATE & THREADING LOCKS
# ==========================================
blocked_ips_cache = set()
last_processed_log_date = None
stop_event = threading.Event()
file_lock = threading.Lock()


def load_blocked_history():
    """Loads previously blocked IPs from disk so they aren't re-blocked on restart."""
    if os.path.exists(BLOCKED_HISTORY_FILE):
        with open(BLOCKED_HISTORY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    blocked_ips_cache.add(ip)
    print(
        f"[INIT] Loaded {len(blocked_ips_cache)} previously blocked IPs into memory."
    )


def log_blocked_ip(ip_str, username, reason_text):
    """Writes a detailed entry to the text log and saves the IP to history."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] BLOCKED IP: {ip_str} | Unapproved User: '{username}' |"
        f" Details: {reason_text}\n"
    )

    with file_lock:
        with open(BLOCKED_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        with open(BLOCKED_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ip_str}\n")

    print(log_entry.strip())


def block_ip_firewall(ip_str):
    """Adds an inbound block rule to Windows Defender Firewall."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        print(f"[WARN] Invalid IP format skipped: {ip_str}")
        return False

    rule_name = f"SQL_AutoBlock_{ip_obj}"
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_obj}",
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    else:
        print(f"[ERROR] Failed to block {ip_obj} in Firewall: {result.stderr}")
        return False


def get_db_connection():
    """Establishes a connection to SQL Server."""
    if SQL_CONFIG["trusted_connection"].lower() == "yes":
        conn_str = (
            f"DRIVER={SQL_CONFIG['driver']};"
            f"SERVER={SQL_CONFIG['server']};"
            f"DATABASE={SQL_CONFIG['database']};"
            "Trusted_Connection=yes;"
        )
    else:
        conn_str = (
            f"DRIVER={SQL_CONFIG['driver']};"
            f"SERVER={SQL_CONFIG['server']};"
            f"DATABASE={SQL_CONFIG['database']};"
            f"UID={SQL_CONFIG['uid']};"
            f"PWD={SQL_CONFIG['pwd']};"
        )
    return pyodbc.connect(conn_str)


def parse_and_enforce(log_date, process_info, text):
    """Parses a single error log row and blocks the IP if username is not exempted."""
    # Extract username: e.g., Login failed for user 'sa' or Login succeeded for user 'admin'
    user_match = re.search(r"for user '([^']+)'", text, re.IGNORECASE)
    # Extract client IP: e.g., [CLIENT: 192.168.1.50]
    ip_match = re.search(r"\[CLIENT:\s*([^\]]+)\]", text, re.IGNORECASE)

    if not user_match or not ip_match:
        return

    username = user_match.group(1).strip()
    client_ip = ip_match.group(1).strip()

    # 1. Check if username is in the exempt array (case-insensitive)
    if any(username.lower() == exempt.lower() for exempt in EXEMPT_USERS):
        return

    # 2. Check if IP is whitelisted/exempt
    if client_ip in EXEMPT_IPS:
        return

    # 3. Prevent re-blocking if already blocked
    if client_ip in blocked_ips_cache:
        return

    # 4. Execute firewall block and log
    if block_ip_firewall(client_ip):
        blocked_ips_cache.add(client_ip)
        log_blocked_ip(client_ip, username, text)


def monitor_logs_worker():
    """Background worker thread that polls xp_readerrorlog every 60 seconds."""
    global last_processed_log_date

    while not stop_event.is_set():
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            if last_processed_log_date is None:
                print(
                    "[INFO] Performing initial full scan of active SQL Error"
                    " Log..."
                )
                cursor.execute("EXEC sys.xp_readerrorlog 0, 1, N'Login';")
            else:
                start_time_str = last_processed_log_date.strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )[:-3]
                cursor.execute(
                    "EXEC sys.xp_readerrorlog 0, 1, N'Login', NULL, ?;",
                    start_time_str,
                )

            rows = cursor.fetchall()
            newest_date_in_batch = last_processed_log_date

            for row in rows:
                log_date, process_info, text = row[0], row[1], row[2]

                if (
                    last_processed_log_date is not None
                    and log_date <= last_processed_log_date
                ):
                    continue

                if (
                    newest_date_in_batch is None
                    or log_date > newest_date_in_batch
                ):
                    newest_date_in_batch = log_date

                parse_and_enforce(log_date, process_info, text)

            if newest_date_in_batch is not None:
                last_processed_log_date = newest_date_in_batch

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"[ERROR] Database or polling error: {e}")

        stop_event.wait(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    print("=== SQL Server Strict Allowlist Auto-Blocker Started ===")
    print(f"[INIT] Exempted Usernames: {EXEMPT_USERS}")
    load_blocked_history()

    worker_thread = threading.Thread(target=monitor_logs_worker, daemon=True)
    worker_thread.start()

    try:
        while worker_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down background monitor...")
        stop_event.set()
        worker_thread.join(timeout=5)
        print("[INFO] Exited cleanly.")
