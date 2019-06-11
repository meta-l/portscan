# portscan
Created so that there is basic port scan functionality with only PS available. Mainly also a PS learning crutch.

.SYNOPSIS
Scan IP addresses for open ports
.DESCRIPTION
Basic port scanner to scan a single or range of IP addresses, will resolve and randomise chosen IP range if required.
.PARAMETER IPAddress
Starting IP address, ending IP address. If no end supplied, only starting IP Address will be used.
.PARAMETER Ports
Array of target port(s). Required.
.PARAMETER infile
TExt file of IP addresses, one per line. Must either specify this option or give an IP address. Otherwise there's no point. (Mandatory false for these options so the logic works properly)
.PARAMETER randomise
Randomise scan of IP addresses and ports
.PARAMETER portRange
Treat input array of target ports as a range, with input defining start and end; otherwise will be treated as individual, numbered ports
.PARAMETER resolve
Attempt to use DNS to resolve IP address (much slower)
.PARAMETER delay
Apply a delay of 1-1000 milliseconds before attempting next TCPClient connection
.PARAMETER threads
DEfaults of number of processors on the host running the script, can specify any number. Advise no more than 20.
.EXAMPLE
.\portscan.ps1 -ipaddress 127.0.0.1,127.0.0.4 -ports 445 (Scan port 445 on IP addresses 127.0.0.1 - 127.0.0.4)
.EXAMPLE
.\portscan.ps1 -ipaddress 127.0.0.1 -ports 445,3389,23 -randomise -resolve (Scan ports 23,445,3389 on IP 127.0.0.1 randomly and resolve the IPs)
.EXAMPLE
.\portscan.ps1 -infile .\targets.txt -portrange 445,450 (Scan ports 445 through 450 inclusive on hosts specified in targets.txt)
.NOTES
Version: 0.7_1
*0.1: Accept command line parameters, validate IP addresses. Thanks to @darkoperator for validation tip
*0.2: detect single IP or scan range, iterate accordingly
*0.3: detect single port or range, iterate accordingly
*0.4: error checking, graceful exits etc. (kind of - errors silently suppressed to allow orderly text output)
*0.5: randomise IP/ports order (initial random of IP). Refactored to not need IP validation, IP/port detection range works properly
*0.6: allow for range of ports (has broken numbered, single ports)
*0.6_2: Fixed single ports
*0.6_3: Added scan delay. Kind of a bodge until jobs are in place.
*0.6_4: Might be interesting to randomise delay time between 0 and given delay. Then again, it might not :P
*0.6_5: File of IP addresses
*0.7_1: Threads!
*0.7_2: rate adjustment (specify number of threads.)
