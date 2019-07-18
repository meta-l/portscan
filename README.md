# portscan
Created so that there is basic port scan functionality with only PS available. Mainly also a PS learning crutch.

Ver: 0.7.4

Can take a file of IPs, a list of ports, a range of ports and IPs, can randomise the order of ports and IPs, can resolve IPs, can introduce a (pseudo)random delay between 0 and 1000ms, uses threads (runspaces). Threads default to number of cores, can specify more or less, can also specify process priority switch to make process high priority.

Examples:

.\portscan.ps1 -ipaddress 127.0.0.1,127.0.0.4 -ports 445

.\portscan.ps1 -ipaddress 127.0.0.1 -ports 445,3389,23 -randomise -resolve

.\portscan.ps1 -infile .\targets.txt -portrange 445,450 -threads 10

Version history

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
    *0.7_3: Added priority switch
    *0.7_4: Added infopane when started
    Roadmap 0.8: output formatting
    Roadmap 0.9: get banners/versions
