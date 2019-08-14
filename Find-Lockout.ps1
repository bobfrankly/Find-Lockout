function Find-Lockout{
    [cmdletbinding()]
    param(
        [string]$targetUser
    )
    # Populate current Domain Controllers
    $controllers = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers.name

    # Regex Filter to pull IP address
    $rFilter = "(?<=Client Address:\s*::ffff:)(\d*.\d*.\d*.\d*)"
    # xPath filter to target specific events
    $xPath = " *[EventData[Data[@Name='TargetUserName'] and (Data='" + $targetUser + "')]]"

    
    # Search the Event logs of each DC. =========================================================================
    $results = $null
    $results = foreach ($dc in $controllers){
        Write-Verbose "Scanning $dc"
        try{
        Get-WinEvent -computername $dc -FilterXPath $xPath -ea Stop -verbose:$false
        }
        catch
        [System.Exception]
        {
            $_.fullyqualifiederrorid
            write-verbose "---- No Matches on $dc"    
        }
    }
    

    [array]$ipaddy = " "
    # Pull the IP address out of the message text of each matching event
    foreach ($pop in $results){
        $get = ([regex]$rFilter).match($pop.message).value
        if ($get -ne ""){
            # $get
            $ipaddy += $get
        }
    }
    
    $uniques = $ipaddy | Select -Unique
    foreach ($ip in $uniques){
        $count = $ipaddy | Where-Object {$_ -eq $IP} | Measure-Object | Select -expand Count
        
        try{
            $reverseLU = [System.Net.DNS]::GetHostEntry($ip) | Select-object -expand HostName
        }
        catch{
            $reverseLU = "Unknown"
        }
        
        # Output
        "" | Select-Object @{n='ip' ; e={$ip}}, @{n="count" ; e={$count}}, @{n="hostName" ; e={$reverseLU}}
    }
    
}
