# portscan
Created so that there is basic port scan functionality with only PS available. Mainly also a PS learning crutch.

Ver: 0.7.1

Can take a file of IPs, a list of ports, a range of ports and IPs, can randomise the order of ports and IPs, can resolve IPs, can introduce a (pseudo)random delay between 0 and 1000ms, uses threads (runspaces). Threads default to number of cores, can specify more or less.

Examples:

.\portscan.ps1 -ipaddress 127.0.0.1,127.0.0.4 -ports 445

.\portscan.ps1 -ipaddress 127.0.0.1 -ports 445,3389,23 -randomise -resolve

.\portscan.ps1 -infile .\targets.txt -portrange 445,450 -threads 10
