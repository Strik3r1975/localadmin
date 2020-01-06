# Autor: Patrick Strijkers (aka Strik3R1975)
# Date: 2020/01/01
# Version 0.5
# Last Mofified date: 2020/01/06
# Last Modified by: Patrick Strijkers
# Description: This script will enumerate the (effective) membership of a local group. The output will be a CSV file that contains the following columns:
# You need to use a normal txt file that contains the servers that needs to be scanned, put the file in the folder \Input\ (filename needs to be 'servers.txt')
# The output file will be called localAdmin.csv and will be placed in the .\Output\ folder
# Version 0.1: 
# Computer Name
# Path of the user (ADSI)
# UserName
# Password last set date
#
# Version 0.2:
# Enumerates the local administrators remote
#
# Version 0.3:
# Added error Logging and progress logging
#
# Version 0.4:
# Multithreading functionality has been added. 
# You can now run the script in a multithread mode. 
# To enumerate the local administrators in multithreading mode you need to start the script with the parameter -MaxThread and the number of parallel threads executed by the script
#
#Version 0.5
#vAdded a progressbar in single thread mode
# Added scipt comments
# fixed an issue in the mulitthreading mode 
#

Param (
       [string] $ExportCsv = ".\Output\localAdmin.csv",
       [string] $ServerListFile = ".\Input\servers.txt",
       [string] $GroupName = "Administrators",
	   [int]    $MaximumThread = 10,
	   [int]    $SharingTimeOut = 60
)

#Script block for user account enumeration
$EnumAdministrators = 
{
    Param (
        [String] $serverName,
        [string] $Csv,
        [int] $iCsvTimeou = 60

)
      
    #Global Variable
    $aryUsers = @()
    $ErrorLogFile = $MyInvocation.MyCommand.Name + '_error.log'


    #Get-ADGroupMember enumerate all members of this group
    #Param $ADSPath is the ADSI Path for the group
    #Return value is a array of users ADSI path
    function Get-ADGroupMembers($ADSPath)
    {
    $RetVal = @()
    $ADmember = [ADSI]$ADSPath
    if ($admember.SchemaClassName -eq "Group")
    {
        foreach ($member in $ADmember.psbase.Invoke('Members'))
        {
            $memberADSPath = $member.GetType().InvokeMember('ADSPath','GetProperty',$null,$member,$null)
            If ($member.GetType().InvokeMember('Class','GetProperty',$null,$member,$null) -eq 'Group')
            {
                foreach ($m in Get-ADGroupMembers($memberADSPath))
                {
                        $retVal += $m
                }
            }
            else
            {
                    $retVal += $MemberAdsPath
            }
        }
    }
    else
    {
       $RetVal += $ADSPath
     
    }    
    return $RetVal
}

    #Get-UserData enumerates the user details
    #Param $ADS path is the ADSI path of the user
    #Return value: Is a string with the name of the analyzed computer, the ADSI path of the user, SAMAccountName, last password set date
    function Get-UserData($AdsPath)
    {
    $oUser = New-Object PsObject 
    $oAdsiUser = [ADSI]"$AdsPath,user"
    $oUser |Add-Member "Name" $oAdsiUser.Name.Value
    $oUser |Add-Member "Path" $oAdsiUser.Path
    $oUser |Add-Member "PasswordLastSet" (Get-Date).AddSeconds(-$oAdsiUser.PasswordAge.Value)
    try
    {
        $oUser |Add-Member "LastLogon" $oAdsiUser.LastLogin.value 
    }
    catch
    {
        $oUser |Add-Member "LastLogon" $null
    }
    try
    {
        if ($ouser.PasswordAge.psbase.value -like 0)
        { $active = $false}
        else
        { $active = $true}
    }
    catch
    {
        $active = $true
    }
    $oUser| Add-Member "Active" $active

    Return $oUser
}

    Function WriteErrorLog($Computer,$ErrorMessage, $ErrorLevel)
    {
    $Now = Get-Date -Format u
    if (!(Test-Path $ErrorLogFile))
    {
        New-Item $ErrorLogFile -Force -ItemType File
    }
     $now.ToString() + ',' + $Computer + ',' + $ErrorLevel + ',' + $ErrorMessage | Add-Content $ErrorLogFile
}

    #Get-WindowsName return the name of the local user or group based on the local SID
    #$computer is the name of the computer
    #$SID is the SID of the user or group
    #
    #Return ist the ADSI path of the SID
    Function Get-WindowsAccountPath ([string]$Computer, [String]$SID) 
    {
        
        $computer = $computer.Trim()
        $retVal = $null
        $oComputer = [ADSI]"WinNT://$Computer"
        $oLocalGroups = $oCOmputer.psbase.Children | where {$_.SchemaClassName -match "group|user"} 
        Foreach ($oLocalGroup in $oLocalGroups)
        {
            if ((New-Object System.Security.Principal.SecurityIdentifier $oLocalGroup.ObjectSid[0],0).Value -match $SID)
            {
                $RetVal = $oLocalGroup.Name 
                Break
            }
        }
        Return $RetVal
    }

    #Get-LocalAdministratorsGroupPath enumerates the ADSI path of a local Administrator group
    Function Get-LocalAdministratorsGroupPath ([string]$Computer)
    {
        
        $RetVal = Get-WindowsAccountPath $Computer "S-1-5-32-544"
       
        Return $RetVal
    }

    #Get-LocalBackupOperatorsGroupPath retruns the ADSI Path of the local Backup Operators
    #$computer is the name of the computer to enumerate
    #return the ADSI path of the local Backup Operators group
    Function Get-LocalBackupOperatorsGroupPath ([string]$Computer)
{
    Return Get-WindowsAccountPath $Computer "S-1-5-32-551"
}

    #Get-LocalBackupOperatorsGroupPath retruns the ADSI Path of the local Administrators
    #$computer is the name of the computer to enumerate
    #return the ADSI path of the local Administrators group
    Function Get-LocalAdministratorPath([string]$computer)
    {
    return Get-WindowsAccountPath $computer "S-1-5-32-500"
}


    Function EnumLocalAdministrators($computer) 
    {
        $oUserList = @()
        $computer = $computer.Trim()
        try
        {
            $oAdministratorsGroupName = Get-LocalAdministratorsGroupPath $computer
            $oGroupMembers = ([ADSI]"WinNT://$Computer/$oAdministratorsGroupName,group").psbase.Invoke('Members')
            foreach ($Groupmember in $oGroupMembers)
            {
                $GroupmemberADSPath = $GroupMember.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $GroupMember, $null)
                switch ($GroupMember.GetType().InvokeMember('Class','GetProperty',$null,$GroupMember,$null))
                {
                    "User"  {
                                $user = Get-UserData($GroupMemberADSPath)
                                $user |Add-Member "Computer" $computer 
                                $user |Add-Member "MemberOf" $oAdministratorsGroupName
                                if (@($oUserList |Where-Object {$_.Path -like $user.Path}).Count -eq 0)
                                {
                                    $oUserList += $user
                                }
                            }
                    "Group" {
                                Foreach ($userADSPath in Get-ADGroupMembers($GroupMemberADSPath))
                                {
                                    $user = Get-UserData($userADSPath)
                                    $user |Add-Member "Computer" $computer
                                    $user |Add-Member "MemberOf" $oAdministratorsGroupName
                                    if (@($oUserList |Where-Object {$_.Path -like $user.Path}).Count -eq 0)
                                    {
                                        $oUserList += $user
                                    }
                                }
                            }
                }
            }
            Return $oUserList       
        }
        catch [Exception] 
        {
            Write-Host "Error: $computer $_"
            WriteErrorLog $computer $_ "Critical"
            
        }
    }

    $Administrators = EnumLocalAdministrators $serverName
    Write-Host "Found $($Administrators.count) Administrators on $serverName"
    $dTimeOut = (Get-Date).AddSeconds($iCsvTimeout)
    $bWriteSuccess = $false
    do
    {
        try
        {
            #$ErrorActionPreference = 'SilentlyContinue'
            $Administrators|Export-Csv $Csv -NoTypeInformation -Append
            $bWriteSuccess = $true
            Break
        }
        catch [AccessViolationException]
        {
            Write-host "Access vaiolation"
            sleep -Milliseconds (random -Minimum 100 -Maximum 2000)
        }
    }while ((Get-Date) -lt $dTimeOut)
    if (!$bWriteSuccess)
    {
        WriteErrorLog($ServerName,$Error, "Critical")
    }
}

#Fuction to display the progress bar in multithreading mode
Function Write-JobProgress
{
    $JobName = $null
    ForEach ($bj in $(Get-Job -State Running)){$JobName+= ", $($bj.Name)"}
    Write-Progress -Activity "Enumeration in progress" -Status "$($(Get-Job -State Running).count) threads remaining" -CurrentOperation $JobName -PercentComplete ($(Get-Job -State Completed).count / $(Get-Job).count * 100)
}

#Main Programm starts here
#Delete existing CSV files and create a new file 
if (Test-Path "$ExportCsv")
{
    Remove-Item "$ExportCsv" -Force
}
#Getting the full filename and Path and write it to the $ExportCSV variabel. This is required if the ExportCSV parameter contains a relative name
$oResultFile = New-Item $ExportCsv -ItemType File -Force
$ExportCsv = $oResultFile.FullName


#check the server list file. If it's not available use the local host and write the content of the server list to $serverList. $serverList will be used in the next step
if (!(Test-Path $ServerListFile))
{
    $serverList = $env:COMPUTERNAME
}
else
{
    $ServerList = Get-Content $ServerListFile
}

#Validate if the scipt runs in Mulitthreading Mode or as single thread
#If the script parameter $MaximumThread is 1 the script runs in single task mode
If ($MaximumThread -eq 1)
{
    $iServerCount = 0
    $iAllServer = $serverList.Count
    Foreach ($Server in $ServerList)
    {
        $iServerCount++
        Write-Progress -Activity "Enumeration in progress" -CurrentOperation "working on $Server $iServerCount of $iAllServer" -PercentComplete ($iServerCount / $iAllServer * 100)
        $Server = $Server.Trim()
        Invoke-Command -ScriptBlock $EnumAdministrators -ArgumentList $Server, $ExportCsv, $SharingTimeOut
        
    }
}
else
{
    $i = 0
    $iServerCount = $serverList.Count
    Foreach ($Server in $ServerList)
    {
        $i++
        if ((Get-Job).count -gt 0 )
        {
            While(@(Get-Job | Where-Object { $_.State -eq 'Running'}).count -gt $MaximumThread)
            {
                Sleep 2
            }
        }
        Start-Job -ScriptBlock $EnumAdministrators -ArgumentList $Server, $ExportCsv, $SharingTimeOut -Name $Server 
        Write-Host "Enumerate Server $Server ($i) of $iServerCount Servers"  
        #Get-Job | Where-Object { $_.State -eq 'Running'}|Receive-Job
    }
    While(@(Get-Job | Where-Object { $_.State -eq 'Running'}).count -gt 0)
    {
        Write-JobProgress 
        Sleep 2
    } 
    write-host "all server enumerated"
}
