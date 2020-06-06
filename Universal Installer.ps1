<# *******************Script Information*************************************************
Script Name: Universal Installer
Author: Brian C. Sharp
Brief Description: Easy to use script for designed for SCCM insallations. Script does not require any modification to run just use the paramenters, can provide easy to read log and registry branding.
Current Script capabilities include the following actions
MSI Installation
Running EXE
Copying Files
Adding registry information using reg files


Example - File Copy
'.\Global Installer.ps1' -ARPDisplayName "Mozilla Firefox 76.0.1 (x64 en-us)" -ARPVersion 76.0.1 -Revision R.1.0 -ActionType "Copy" -srcDirectory "Mozilla Firefox"  -DestDirectory "C:\Mozilla Firefox" -EnableScriptLogging $True

Example - Registry Import
'.\Global Installer.ps1' -ARPDisplayName "Mozilla Firefox 76.0.1 (x64 en-us)" -ARPVersion 76.0.1 -Revision R.1.0 -ActionType "Registry" -EnableScriptLogging $True

Example - MSI
'.\Global Installer.ps1' -InstallerFile "Firefox Setup 76.0.1.msi" -InstallArguments "/QN" -ARPDisplayName "Mozilla Firefox 76.0.1 (x64 en-us)"  -ARPVersion 76.0.1 -Revision R.1.0 -ActionType "Install" -EnableScriptLogging $True -VerifyApplication $true


Example - MSI with MST
'.\Global Installer.ps1' -InstallerFile "Firefox Setup 76.0.1.msi" -MSTFile "Firefox.mst" -InstallArguments "/QN" -ARPDisplayName "Mozilla Firefox 76.0.1 (x64 en-us)" -ARPVersion 76.0.1 -Revision R.1.0 -ActionType "Install" -EnableScriptLogging $True


Example - exe file
'.\Global Installer.ps1' -InstallerFile "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" -InstallArguments "/S" -ARPDisplayName "Mozilla Firefox 76.0.1 (x64 en-us)" -ARPVersion 76.0.1 -Revision R.1.0 -ActionType "Uninstall" -EnableScriptLogging $True

-Processes used to stop running processes
Example: -process "firefox","Chrome","Notepad"

-PackagerEmail used to brand registry with packagers email
Example: -PackagerEmail "myEmail@myDomain.com"

-ScriptLogLocation used to change default location of the Script log (Default Location: c:\windows\logs)
Example: -ScriptLogLocation "c:\SCCMLogging"

-MSILogLocation used to change default location of the MSI log (Default Location: c:\windows\logs\msi)
Example: -MSILogLocation "c:\SCCM\MSILogs"

-CustomExitCode used to provide a custom exit code which indicates success
Example: -CustomExitCode "3010"

-DestDirectory used to denote the copy to location when -ActionType is Copy
Example: -ActionType "Copy" -DestDirectory "c:\MyFiles"

-srcDirectory used to denote the source location when -ActionType is Regsitry or -ActionType is Copy. Default location is the script root. Default value is $PSScriptRoot
Example: -ActionType "Copy" -srcDirectory "d:\MyFiles" -DestDirectory "c:\MyFiles"

-RegistryBranding used to enable or disable Registry Branding. Default Value is $True
Example: -RegistryBranding $False

-EnableScriptLogging  used to enable or disable Script Logging. Default value is $False
Example: -EnableScriptLogging $True

-ImportRegistry Used with ActionType Install to install a application and Import registry keys for configuration. Default Value $False
Example:'.\Global Installer.ps1' -InstallerFile "Firefox Setup 76.0.1.msi" -InstallArguments "/QN" -ARPDisplayName "Mozilla Firefox 76.0.1 (x64 en-us)"  -ARPVersion 76.0.1 -Revision R.1.0 -ActionType "Install" -ImportRegistry $True -srcDirectory RegistryFiles

<# ************************************************************************************** #>


<# Parameters required #> 
    param(
    [Parameter()]
    [String[]]$Processes,
    
    [Parameter()]
    [String]$InstallerFile,

    [Parameter()]
    [String]$MstFile,

    [Parameter()]
    [String]$InstallArguments,

    [Parameter(Mandatory=$true)]
    [String]$ActionType,
    
    [Parameter(Mandatory=$true)]
    [String]$Revision,
    
    [Parameter(Mandatory=$true)]
    [String]$ARPVersion,

    [Parameter(Mandatory=$true)]
    [String]$ARPDisplayName,

    [Parameter()]
    [String]$PackagerEmail,
    
    [Parameter()]
    [String]$VerifyApplication = $True,

    [Parameter()]
    [String]$ScriptLogLocation = "c:\windows\logs",

    [Parameter()]
    [String]$MSILogLocation = "c:\windows\logs\msi",

    [Parameter()]
    [String]$CustomExitCode = 1000005, #<---The $CustomExitCode has a default value so it does not evaluate as $null. Recommend only to change this value if conflicting with another exit code.

    [Parameter()]
    [String]$DestDirectory,

    [Parameter()]
    [String]$srcDirectory = $PSScriptRoot,

    [Parameter()]
    [BOOL]$RegistryBranding = $true,

    [Parameter()]
    [BOOL]$EnableScriptLogging = $False,

    [Parameter()]
    [BOOL]$ImportRegistry = $false

    )

<# Functions #>
  Function LogInstallationActions
    {
                if ($EnableScriptLogging -eq $true)
                    {
                        $LogName = "$ARPDisplayName" + "_" + $ARPVersion + "_" + $Revision + "_" + "$ActionType" + ".log"
                        "[" + (Get-Date -UFormat "%m/%d/%Y %r") + "]" + $logString | Out-File "$ScriptLogLocation\$LogName" -Append
                    }
    }


Function Kill-Process
    {
      ForEach ($Process in $Processes) 
        {
            If (Get-Process | Where-Object {$_.ProcessName -eq $Process})
                {
                    $logString = "Stopping Process $Process"
                    LogInstallationActions
                    Stop-Process -Name $Process -Force
                }
        }
    }


    Function Install-Application
        {
            If ($InstallerFile.EndsWith('msi'))
               {
                    $logString = "Starting install of MSI File: $InstallerFile"
                    LogInstallationActions

                    $strInstallerFile =  "`"$InstallerFile`""
                    $FullLogName = $InstallerFile.Substring(0, $InstallerFile.Length -4)
                    $strMSILogLocation = "`"$MSILogLocation\$FullLogName" + "_" + "$ActionType" + ".log`""
                    If ($MstFile -eq "")
                        {
                            $logString = "Execution command: msiexec.exe /i $strInstallerFile /l*v $strMSILogLocation $InstallArguments"
                            LogInstallationActions
                            $logString = "Starting Install...If I’m not back in five minutes, just wait longer.”
                            LogInstallationActions
                            $ProcessMonitor =  Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $strInstallerFile /l*v $strMSILogLocation $InstallArguments" -Wait -PassThru
                            $errorcount = $errorcount + $ProcessMonitor.ExitCode
                            $logString = "Process Completed with Exit Code: $errorcount"
                            LogInstallationActions
                            MSIExitCodeInformation
                            $logString = "For more detailed information about this MSI Install view $strMSILogLocation"
                            LogInstallationActions
                        }  
                    Else
                        {
                            $strMstFile = "`"$MstFile`""
                            $logString = "Execution command: msiexec.exe /i $strInstallerFile /t $strMstFile /l*v $strMSILogLocation $InstallArguments"
                            LogInstallationActions
                            $logString = "Starting Install...If I’m not back in five minutes, just wait longer.”
                            LogInstallationActions
                            $ProcessMonitor = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $strInstallerFile /t $strMstFile /l*v $strMSILogLocation $InstallArguments" -Wait -PassThru
                            $errorcount = $errorcount + $ProcessMonitor.ExitCode
                            $logString = "Process Completed with Exit Code: $errorcount"
                            LogInstallationActions
                            MSIExitCodeInformation
                            $logString = "For more detailed information about this MSI Install view $strMSILogLocation"
                            LogInstallationActions
                        }  
               }


            If ($InstallerFile.EndsWith('msp'))
                {
                    $strInstallerFile =  "`"$InstallerFile`""
                    $FullLogName = $InstallerFile.Substring(0, $InstallerFile.Length -4)
                    $strMSILogLocation = "`"$MSILogLocation\$FullLogName" + "_" + "$ActionType" + ".log`""
                    $logString = "Starting install of MSP File"
                    LogInstallationActions 
                    $logString = "Execution command: msiexec.exe /p $strInstallerFile /l*v $strMSILogLocation $InstallArguments"
                    LogInstallationActions
                    $logString = "Starting Install...If I’m not back in five minutes, just wait longer.”
                    LogInstallationActions
                    $ProcessMonitor =  Start-Process -FilePath "msiexec.exe" -ArgumentList "/p $strInstallerFile /l*v $strMSILogLocation $InstallArguments" -Wait -PassThru
                    $errorcount = $errorcount + $ProcessMonitor.ExitCode
                    $logString = "Process Completed with Exit Code: $errorcount"
                    LogInstallationActions
                    MSIExitCodeInformation
                    $logString = "For more detailed information about this MSI Install view $strMSILogLocation"
                    LogInstallationActions
                }

            If ($InstallerFile.EndsWith('exe'))
                {
                    $logString = "Starting install of EXE File"
                    LogInstallationActions 
                    $strInstallerFile =  "`"$InstallerFile`""
                    $logString = "Execution command: $strInstallerFile $InstallArguments"
                    LogInstallationActions
                    $logString = "Starting Install...If I’m not back in five minutes, just wait longer.”
                    LogInstallationActions
                    $ProcessMonitor = Start-Process -FilePath $strInstallerFile -ArgumentList "$InstallArguments" -Wait -PassThru
                    $errorcount = $errorcount + $ProcessMonitor.ExitCode
                    $logString = "Process Completed with Exit Code: $errorcount"
                    LogInstallationActions
                    
                }
           $logString = "Exiting Install Application Returning Error Count: $ErrorCount"
           LogInstallationActions 
           Return $errorcount
        }

Function Uninstall-Application
    {
        If ($InstallerFile.EndsWith('msi'))
            {
               $FullLogName = $InstallerFile.Substring(0, $InstallerFile.Length -4)
               $strMSILogLocation = "`"$MSILogLocation\$FullLogName" + "_" + "$ActionType" + ".log`""
               $strInstallerFile =  "`"$InstallerFile`""
               $logString = "Execution command: msiexec.exe /x $strInstallerFile $InstallArguments"
               LogInstallationActions
               $ProcessMonitor = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $strInstallerFile /l*v $strMSILogLocation $InstallArguments" -Wait -PassThru
               $errorcount = $errorcount + $ProcessMonitor.ExitCode
               $logString = "Process Completed with Exit Code: $errorcount"
               LogInstallationActions
               MSIExitCodeInformation
               $logString = "For more detailed information about this MSI Install view $strMSILogLocation"
               LogInstallationActions
            }

        If ($InstallerFile.EndsWith('exe'))
            {
               $InstallerFile =  "`"$InstallerFile`""
               $logString = "Execution command: $InstallerFile $InstallArguments"
               LogInstallationActions
               $ProcessMonitor = Start-Process -FilePath $InstallerFile -ArgumentList "$InstallArguments" -Wait -PassThru
               $errorcount = $errorcount + $ProcessMonitor.ExitCode
               $logString = "Process Completed with Exit Code: $errorcount"
               LogInstallationActions
             }
        $logString = "Exiting Uninstall Application Returning Error Count: $ErrorCount"
        LogInstallationActions 
        Return $errorcount        
    }

Function Regsitry-Branding
    {
        If ($RegistryBranding -eq $true)
            {
                $InstallACCT = WhoAmI
                $logString = "Performing Registry Branding"
                $RegKey = "HKLM:\SOFTWARE\SCCM\$ARPDisplayName" + "_" + $ARPVersion + "_" + $Revision
                LogInstallationActions
                If (!(Test-Path $RegKey))
                    {
                        New-Item $RegKey -Force -ErrorAction SilentlyContinue
                        $LogString = "Created Application Registry Key"
                        LogInstallationActions
                    }
               If ($ActionType -eq "Install")
                    {
                        New-ItemProperty $RegKey -Name Installed -Value $true -PropertyType String -Force -ErrorAction SilentlyContinue
                        $LogString = "Set Value Installed: True"
                        LogInstallationActions
                    }
               If ($ActionType -eq "Uninstall")
                    {
                        New-ItemProperty $RegKey -Name Installed -Value $false -PropertyType String -Force -ErrorAction SilentlyContinue
                        $LogString = "Set Value Installed: False"
                        LogInstallationActions
                    }
               If ($ActionType -eq "Copy")
                    {
                        New-ItemProperty $RegKey -Name Installed -Value "File Copy Only" -PropertyType String -Force -ErrorAction SilentlyContinue
                        $LogString = "Set Value Installed: File Copy Only"
                        LogInstallationActions
                    }


                New-ItemProperty $RegKey -Name Revision -Value $Revision -ErrorAction SilentlyContinue
                $LogString = "Set Value Revision: $Revision"
                LogInstallationActions
                New-ItemProperty $RegKey -Name Version -Value $ARPVersion -ErrorAction SilentlyContinue
                $LogString = "Set Value Version: $ARPVersion"
                LogInstallationActions
                $LogDate = (Get-Date -UFormat "%m/%d/%Y %r")
                New-ItemProperty $RegKey -Name "Modified" -Value $LogDate -PropertyType String -Force -ErrorAction SilentlyContinue
                $LogString = "Set Value Modified: $LogDate"
                LogInstallationActions
                New-ItemProperty $RegKey -Name "Packager Email" -Value $PackagerEmail -ErrorAction SilentlyContinue
                $LogString = "Set Value Packager: $PackagerEmail"
                LogInstallationActions
                New-ItemProperty $RegKey -Name "Install Account" -Value $InstallACCT -ErrorAction SilentlyContinue
                $LogString = "Set Value Install Account: $InstallACCT"
                LogInstallationActions
                New-ItemProperty $RegKey -Name "Action Type" -Value $ActionType -ErrorAction SilentlyContinue
                $LogString = "Set Value Action Type: $ActionType"
                LogInstallationActions
            }
    }



    
    Function VerifyScriptConditions
        {

        #Remove trailing \ if found on Variables containing path locations
        if ($MSILogLocation.EndsWith('\'))
            {
                $MSILogLocation = $MSILogLocation.Substring(0,$MSILogLocation.Length -1)
                $LogLocationValueChanged = $True
            }
        
        if ($ScriptLogLocation.EndsWith('\'))
            {
                $ScriptLogLocation = $ScriptLogLocation.Substring(0,$ScriptLogLocation.Length -1)
                $LogLocationValueChanged = $True
            }

        
        if ($srcDirectory.EndsWith('\'))
            {
                $ScriptLogLocation = $srcDirectory.Substring(0,$srcDirectory.Length -1)
                $LogLocationValueChanged = $True
            }

        if ($DestDirectory.EndsWith('\'))
            {
                $ScriptLogLocation = $DestDirectory.Substring(0,$DestDirectory.Length -1)
                $LogLocationValueChanged = $True
            }
        
        #Verify Existance of Log directories and Create if they do not exist
        If (!(Test-Path $MSILogLocation))
            {
                New-Item -ItemType Directory -Path $MSILogLocation -Force
                $CreateMSILogDirectory = $True
            }
        
        
            If (!(Test-Path $ScriptLogLocation))
                {
                    New-Item -ItemType Directory -Path $ScriptLogLocation -Force
                    $CreateScriptLogDirectory = $True
                }

            if ($CreateMSILogDirectory -eq $True)
                {
                    $logString = "Created new directory: $MSILogLocation"
                    LogInstallationActions
                }

            if ($CreateScriptLogDirectory -eq $True)
                {
                    $logString = "Created new directory: $ScriptLogLocation"
                    LogInstallationActions
                }
            if ($LogLocationValueChanged -eq $True)
                {
                    $logString = "Directory Values auto changed to meet script parameter"
                    LogInstallationActions
                    $logString = '$MSILogLocation: ' + $MSILogLocation
                    LogInstallationActions
                    $logString = '$ScriptLogLocation: ' + $ScriptLogLocation
                    LogInstallationActions
                    $logString = '$srcDirectory: ' + $srcDirectory
                    LogInstallationActions
                    $logString = '$ScriptLogLocation: ' + $ScriptLogLocation
                    LogInstallationActions      
                }
        }  



Function VerifyApplicationWithWMI
    {
        
        $logString = "Attempting to verify Application via SMS WMI Class"
        LogInstallationActions 
        
        If (Get-WmiObject -Class win32_product | Where-Object {$_.Name -eq "Configuration Manager Client"})
            {
                if (Get-WmiObject -Namespace "root\cimv2\sms" -Class SMS_InstalledSoftware | Where-Object {$_.ARPDisplayName -eq $ARPDisplayName} | Where-Object {$_.ProductVersion -eq $ARPVersion})
                    {
                        $logString = "Application Name and Version found in Add\Remove Programs"
                        LogInstallationActions
                        $errorcount = $errorcount + 0
                    }
                 Else
                    {
                        $logString = "Application Name and Version not found in Add\Remove Programs"
                        LogInstallationActions 
                    }
            }
            
        Else
            {
                        $logString = "Warning: Configuration Manager Client Not installed, unable to verify application from this method."
                        LogInstallationActions
                        $errorcount = $errorcount + 1
            }
           $logString = "Exiting Verify Application with WMI Returning Error Count: $ErrorCount"
           LogInstallationActions 
           Return $errorcount 
      
    }


Function Copy-Files
    {
        $logString = "Checking to see if $DestDirectory already exist"
        LogInstallationActions
        If (test-Path $DestDirectory)
            {
                $logString = "Directory Exist"
                LogInstallationActions
                #If Directory found, should it be cleared of existing Files and folders? 
            }
        Else
            {
                $logString = "Directory not found... Creating Directory $DestDirectory"
                LogInstallationActions
                $logString = "Creating directory $DestDirectory"
                LogInstallationActions
                New-Item $DestDirectory -ItemType directory -Force | Out-Null
            }
        $logString = "Everything looks Good....Zhu Li Do the Thing!"
        LogInstallationActions
        $logString = "Hashing Files in $srcDirectory using SHA256 hashing algorithm"
        LogInstallationActions
        $scrDirectoryFiles = Get-ChildItem –Path $srcDirectory | foreach  {Get-FileHash –Path $_.FullName -Algorithm SHA256 | Select Hash}
        $logString = "Hash of Files Found in $srcDirectory"
        LogInstallationActions
        forEach ($Hash in $scrDirectoryFiles.Hash)
            {
                $logString = $Hash
                LogInstallationActions
            }
        $logString = "Copying files from  $srcDirectory to $DestDirectory"
        LogInstallationActions
        $Error.Clear()
        Copy-Item -Path $srcDirectory\* -Destination $DestDirectory -Recurse
        $errorcount = $errorcount + $error.count
        $logString = "Process Completed with Error Count:" + $error.count
        LogInstallationActions
        $logString = "Hashing Files in $DestDirectory"
        LogInstallationActions
        $DestDirectoryFiles = Get-ChildItem –Path $DestDirectory| foreach  {Get-FileHash –Path $_.FullName -Algorithm SHA256 | Select Hash}
        $logString = "Hash of Files Found in $DestDirectory"
        LogInstallationActions
        forEach ($Hash in $DestDirectoryFiles.Hash)
            {
                $logString = $Hash
                LogInstallationActions
            }
        if (Compare-object -ReferenceObject $scrDirectoryFiles -DifferenceObject $DestDirectoryFiles -IncludeEqual)
                {
                    $errorcount = $errorcount + 0 
                    $logString = "Hash Check was successful, error count: $errorcount"
                    LogInstallationActions          
                }
        Else
                {
                    $errorcount = $errorcount + 1
                    $logString = "File Copy was unsuccessful, error count: $errorcount"
                    LogInstallationActions
                }
        $logString = "Exiting Copy Files Returning Error Count: $ErrorCount"
        LogInstallationActions 
        
        Return $ErrorCount
    }
      

Function MSIExitCodeInformation
    {
        Switch ($errorcount)
            {
                '0' {$logString = "Exit Code 0, life is good take the rest of the day off."}
                '3010' {$logString = "Exit Code 3010, Try Rebooting for the software to complete the installation"}
                '1603' {$logString = "Exit Code 1603, I like to blame the HBSS people for these."}
                default {$logString = "Error Code not found check out this Microsoft Technet Article https://docs.microsoft.com/en-us/windows/win32/msi/error-codes for more information"}
            }
        LogInstallationActions
    }

Function ImportRegistryFiles
    {
        $RegFiles = @()
        $RegLocation = $srcDirectory
        
        If(!(Test-Path "$RegLocation"))
            {
                $logString = "$RegLocation does not exst"
                LogInstallationActions
            }  
        Else
            
            {
                $RegFiles = Get-ChildItem -Path $RegLocation -Include *.reg -Recurse
                if ($RegFiles.Count -eq 0)
                    {
                        $logString = "No Regsitry Files Found"
                        LogInstallationActions
                        $errorcount = $errorcount + 1
                        $logString = "Exiting Registry Processing with Error Count: $errorcount"
                        LogInstallationActions
                    }
                Else
                    {
                        $logString = "Found Registry Files"
                        LogInstallationActions
                        ForEach ($RegFile in $RegFiles) 
                            {
                                $logString = "$RegFile"
                                LogInstallationActions
                                $logString = "Starting import of registry files"
                                LogInstallationActions
                                $logString = "Running Command c:\Windows\system32\reg.exe import $RegFile"
                                LogInstallationActions
                                $ProcessMonitor =  Start-Process -FilePath "c:\Windows\system32\reg.exe" -argumentlist "Import $RegFile"  -PassThru -Wait
                                $errorcount = $errorcount + $ProcessMonitor.ExitCode 
                                $logString = "Process Completed with Exit Code:" + $ProcessMonitor.ExitCode
                                LogInstallationActions
                                $errorcount = $errorcount + $ProcessMonitor.ExitCode 
                            } 

                    }

            
           }
           $logString = "Exiting Import Registry Files Returning Error Count: $ErrorCount"
           LogInstallationActions 
           Return $errorcount
    }





#Main
     $errorcount = 0  
      VerifyScriptConditions
      $logString = "Initializing Solution for $ARPDisplayName...Hold onto your butts"
      LogInstallationActions 
      Kill-Process
      If ($ActionType -eq 'Install') 
        {
            $count = Install-Application
            $errorcount = $errorcount + $Count
        }
      
      If ($ActionType -eq 'Uninstall') 
        {
            $count = UninstallApplication
            $errorcount = $errorcount + $Count
        }
      if ($ActionType -eq 'Copy') 
        {
            $errorcount = Copy-Files
            $errorcount = $errorcount + $Count
        }
      if ($ActionType -eq 'Registry' -or $ImportRegistry -eq $True ) 
        {
            $count = ImportRegistryFiles
            $errorcount = $errorcount + $Count
        }
      If ($VerifyApplication -eq $true -and $ActionType -eq "Install") 
        {
            $count = VerifyApplicationWithWMI
            $errorcount = $errorcount + $Count
        }

      If ($errorcount -eq 0 -or $errorcount -eq $CustomExitCode) 
        {
            Regsitry-Branding
        }
      Else
        {
            $logString = "Invalid Exit Code...Installation Failure" 
            LogInstallationActions 
        }
        $logString = "Script Complete...Goodbye"
        LogInstallationActions