# EggIpBlocker
local firewall security
To Do: Create new admin users for your server, save the python script as an exe file

Note: Modify the prompt according to your needs can also be use in the vistitor logs of your web application for users that uses vpn 
"Create a script that will login to my microsoft sql server and read the xp_readerrorlog and block all the ip address that will use the username sa and create an array of all username that will be exempted, also create a text log on the blocked ip address, the script should run in the background proccess use threading and prevent the reblocking of ip address and read xp_readerrorlog rows atleast once, and re.read the xp_readerrorlog  new logs after a minute"

To Unblock IP address:

1. Remove the Rule from Windows Defender Firewall (Required)

You can do this either through the visual interface or via an Administrator Command Prompt:

Option A: Using the Windows Firewall Interface (GUI)

1. Press Win + R, type wf.msc, and press Enter to open Windows Defender Firewall with Advanced Security.
2. Click Inbound Rules in the left sidebar.
3. Scroll down to find rules starting with SQL_AutoBlock_ (for example, SQL_AutoBlock_203.0.113.45).
4. Right-click the rule for the IP you want to unblock and select Delete (or Disable Rule).

Option B: Using Command Prompt (Faster)

Open Command Prompt as Administrator and run this command (replace 203.0.113.45 with the IP you want to unblock):
cmd
netsh advfirewall firewall delete rule name="SQL_AutoBlo
