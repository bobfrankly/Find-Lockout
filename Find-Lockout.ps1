# Run this file to load the function into memory for console use, or dot-source this file to use the function in another script.
# Example Usage:     ps> Find-Lockout BobFrankly
function Find-Lockout{
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
        Write-Host -ForegroundColor Green "Scanning $dc"
        try{
        Get-WinEvent -computername $dc -FilterXPath $xPath -ea Stop
        }
        catch
        [System.Exception]
        {
            $_.fullyqualifiederrorid
            write-host -ForegroundColor Yellow "No Matches on $dc"    
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
            $reverseLU = [System.Net.DNS]::GetHostEntry($ip) | Select -expand HostName
        }
        catch{
            $reverseLU = "Unknown"
        }
        
        
        "" | Select @{n='ip' ; e={$ip}}, @{n="count" ; e={$count}}, @{n="hostName" ; e={$reverseLU}}
    }
    
    #Return the Final list
    # $ipAddy

}
