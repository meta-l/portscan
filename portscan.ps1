<#
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
.EXAMPLE
.\portscan.ps1 -ipaddress 127.0.0.1,127.0.0.4 -ports 445 (Scan port 445 on IP addresses 127.0.0.1 - 127.0.0.4)
.EXAMPLE
.\portscan.ps1 -ipaddress 127.0.0.1 -ports 445,3389,23 -randomise -resolve (Scan ports 23,445,3389 on IP 127.0.0.1 randomly and resolve the IPs)
.EXAMPLE
.\portscan.ps1 -infile .\targets.txt -portrange 445,450 (Scan ports 445 through 450 inclusive on hosts specified in targets.txt)
.NOTES
Version: 0.6_5
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
Roadmap 0_6_6: Graceful errors if no IP addresses entered, rather than the red text of powershell failure
Roadmap 0.7: rate adjustment + jobs
Roadmap 0.8: output formatting
Roadmap 0.9: get banners/versions
Roadmap 0.9_5: Presume could do away with port exist if statement using parameter validation? Investigate
#>

[cmdletbinding()]

Param(
 [Parameter(Mandatory=$true,Position = 0,ParameterSetName="nofile")][System.Net.IPAddress[]]$IPAddress
 ,[Parameter(Mandatory=$true,Position = 1)][Int[]]$ports
 ,[Parameter(Mandatory=$true,ParameterSetName="file")]$inFile
 ,[Switch]$randomise
 ,[Switch]$portRange
 ,[Switch]$resolve
 ,[Switch]$delay)

#region Initialisation

$ErrorActionPreference = "SilentlyContinue"
$DebugPreference = "Continue"
$StartIPAddress, $EndIPAddress = $IPAddress
$startPort, $endPort = $ports

#endregion Initialisation

#region Process

function makeRange {
 $ScanIPRange = @()
 # Check for file specified on command line, populate IPAddress vars
 if($inFile) {
  Get-Content $inFile | ForEach-Object {
  [system.net.ipaddress[]]$ipArrayFromFile = Get-Content $inFile
  $StartIPAddress = $ipArrayFromFile[0]
  $EndIPAddress = $ipArrayFromFile[-1]
  }
 }
 # Generate range of IPs, or just return a single IP if only one specified on command line
 if($EndIPAddress) {
  # Many thanks to Dr. Tobias Weltner, MVP PowerShell and Grant Ward for IP range generator
  # Process Starting IP Address
  $StartIP = $StartIPAddress -split '\.'
  [Array]::Reverse($StartIP)
  $StartIP = ([System.Net.IPAddress]($StartIP -join '.')).Address
  # Process ending IP address
  $EndIP = $EndIPAddress -split '\.'
  [Array]::Reverse($EndIP)
  $EndIP = ([System.Net.IPAddress]($EndIP -join '.')).Address
  # Populate array with IP range           
   For ($x=$StartIP; $x -le $EndIP; $x++) {
    $i = [System.Net.IPAddress]$x -split '\.'
    [Array]::Reverse($i)
    $ScanIPRange += $i -join '.'
   }
 }
 else {
  return $StartIPAddress
 }
return $ScanIPRange
}

# Populate port array if specified
function makePortRange {
 $scanPortRange = @()
 if($portRange) {
  if($ports.Count -ge 3) {write-host "{!} Too many port arguments to calculate range. Try removing the -pR switch or specify only 2 ports. Exiting..." -ForegroundColor Cyan;Exit}
  $scanPortRange = ($startPort..$endPort | ForEach-Object {$_})
 }
 else {
  return $ports
 }

return $scanPortRange
}

# Resolve domains if specified
function getDNS {
$resolveArray = makeRange
Write-Host "{*}=======Resolving=======" -ForegroundColor Magenta
 foreach($rIP in $resolveArray) {
  $hName = $null
  $hName = [System.Net.Dns]::GetHostEntry($rIP).Hostname
  if ($hName) {
   Write-Host $rIP resolves to $hName -ForegroundColor Yellow }
  else {
   Write-Host $rIP does not resolve -ForegroundColor Red }
 }
 Write-Host "{*}=======================" -ForegroundColor Magenta
}

# Standard TCP connect
function doConnect {
 # Connects to IPs in order
 $ipLoopCount = 0
 $portLoopCount = 0
 $ipArray = makeRange
 $portArray = makePortRange
  foreach($nIP in $ipArray) {
  $ipLoopCount++
  foreach($nPort in $portArray) {
   Write-Progress -Activity "Scan range $StartIPaddress - $EndIPAddress" -Status "% Complete:" -PercentComplete((($portLoopCount)/($ipArray.Length*$portArray.Length))*100)
   $portLoopCount++
   if($delay) {$delay = Get-Random -maximum 1000 -Minimum 1; Start-Sleep -m $delay}
   $socket = New-Object System.Net.Sockets.TcpClient
   $socket.Connect($nIP,$nPort)
   if ($socket.Connected) {
    Write-Host $nIP $nPort -ForegroundColor Green -Separator " ==> "}
 <#   $stream = $socket.GetStream()
    Start-Sleep -m 500; $banner=""
    while ($stream.DataAvailable) {$banner+=[char]$stream.ReadByte()}
    write-host $banner -ForegroundColor Blue
    Write-Debug "`$banner is $banner"#>
   else {
    Write-Host $nIP $nPort -ForegroundColor red -Separator " - {!} cannot open socket on port "}
   $socket.Close()
  }
 }
}

# Random IP/port connect
function doConnectRandom {
 # Randomises IP and ports arrays, iterates on IP
 write-verbose "{!} This is Gold Leader. We're starting our attack run."
 $loopcount = 0
 $rPortArray = makePortRange | Sort-Object {Get-Random}
 foreach($rIP in ($randomIP = makeRange | Sort-Object {Get-Random})) {
  #$loopcount++
  foreach($rPort in $rPortArray) {
   Write-Progress -Activity "Scan range $StartIPaddress - $EndIPAddress" -Status "% Complete:" -PercentComplete(($loopcount/($randomIP.Length*$rPortArray.Length))*100)
   $loopcount++
   if($delay) {$delay = Get-Random -maximum 1000 -Minimum 1; Start-Sleep -m $delay}
   $socket = New-Object System.Net.Sockets.TcpClient
   $socket.Connect($rIP,$rPort)
   if ($socket.Connected) {
    Write-Host $rIP $rPort -ForegroundColor Green -Separator " ==> "}
   else {
    Write-Host $rIP $rPort -ForegroundColor red -Separator " - {!} cannot open socket on port "}
   $socket.Close() 
  }
 }
}


Switch ($PSBoundParameters.GetEnumerator().Where({$_.Value -eq $true}).Key) {
 'resolve' {getDNS}
}

if($randomise){
 doConnectRandom
}
else {
 doConnect
}

#endregion Process

#region Finalise
#endregion Finalise

