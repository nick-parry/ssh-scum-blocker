# ssh-scum-blocker
Block failed and invalid ssh attempts by blackhole'ing IPs with iptables

The goal of this is for me to learn go, while trying to usefully block failed ssh attempts.

Here is the main point of this application:
- tail the log file and get offending ips
- After there have been 5(maxAttempts) such offences, that ip needs to be banned.
- Banned as in iptables drop


Here is the basic flow of this application:
- make sure the user is root
- tail /var/log/auth.log looking for some key patterns
- If you find an ip, save it and its occurences into the state file
- If the ip reaches maxAttempts occurences, block it and mark it as blocked
    Here is the JSON structure of an ip in the state file
    {
        "ip" : "1.2.3.4",
        "numAttempts" : 24,
        "blocked" : true,
    }


Stuff that should be added:
    - We should unban an ip after a given time.
    - We should check the state file and make sure it doesn't grow to much.

