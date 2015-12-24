# ssh-scum-blocker
Block failed and invalid ssh attempts by blackhole'ing IPs with iptables

The goal of this is for me to learn go, while trying to usefully block failed ssh attempts.

Here is the main point of this application:
- tail the log file and get offending ips
- After there have been 5(maxAttempts) such offences, that ip needs to be banned.
- Banned as in iptables drop


Here is the basic flow of this application:
- make sure the user is root
- Make sure you have the basic iptables logging/drop chain
- tail /var/log/auth.log looking for some key patterns
- If you find an ip, save it and its occurences into a list of "scum" objects
- If the ip reaches maxAttempts occurences, block it and mark it as blocked



A more current list of features that I want and those that have been added can
be found in the TODD file.
