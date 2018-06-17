<#	.Description
    This script is intended to be used as Packer Powershell Provisioner to setup a Windows 2016 Server as per standard 
    Security,Registry,Services etc. settings. This script is closely aligned with  Document.
    This script is executed through the Packer Template for Windows Server AMI creation - iihs-windows-2016.json

	.INPUTS
	None

	.Example
	None (Refer iihs-windows-2016.json)

	.Example
	None (Refer iihs-windows-2016.json)

	.Outputs
    Logging to sessoin and written to c:\logs\Configure_Standard_Settings.log (the Script Execution log file)
    Logging Transcript logs to C:\Logs\ami_config_Transcript_Log.log (the Transcript log file)

	.Notes
	AUTHOR: 	Arindam Hazra
	DATE  : 	19-Apr-2014
	REQUIRED UTILITIES: none
	==========================================================================
	CHANGE HISTORY:
	Version				DATE			Initials	   	Description of Change
	v1.0				19 Apr 2018		AH				New Script
#>

$ErrorActionPreference = 'SilentlyContinue'
# $Global:LogPath = "c:\Logs"
$Global:buildPath = "c:\Build"
# $Global:sFullPath = ""
# $Global:amiConfigTranscriptLogFilePath = "c:\Logs\ami_config_Transcript_Log.log"
$Global:strLogDateTimeFormat = "dd-MMM-yyyy HH:mm:ss"

# try{stop-transcript|out-null}
# catch [System.InvalidOperationException]{}

# if(Test-Path -Path $Global:amiConfigTranscriptLogFilePath){Remove-item $Global:amiConfigTranscriptLogFilePath -Force}
# Start-Transcript -path $Global:amiConfigTranscriptLogFilePath -NoClobber -Append -Force

# if (!(Test-Path -path $Global:LogPath)){New-Item $Global:LogPath -Type Directory -Force}
# $Global:sFullPath = Join-Path $Global:LogPath "Configure_Standard_Settings.log"
# If(Test-Path -Path $Global:sFullPath){Remove-Item -Path $Global:sFullPath -Force}
# New-Item -Path $Global:LogPath -Name Configure_Standard_Settings.log –Type File

# Function to create a nice looking log for you 
# function Write-LogSectionHeader {
	# <#	.Description
		# Function to write a standard log section "header" with desired formatting and date/time info
	##>
	# param(
		# [parameter(Mandatory=$true)][string]$Header_str,
		# [string]$LogFilespec_str = $Global:sFullPath
	# )

	# "$((Get-Date).ToString($Global:strLogDateTimeFormat)) : ${Header_str}..." | Out-File $LogFilespec_str -append
	# "*" * 60 | Out-File $LogFilespec_str -append
	# Write-Host "$((Get-Date).ToString($Global:strLogDateTimeFormat)) : ${Header_str}...`n`r" -foregroundcolor green
# }

Function SetService()
{
   	<#	.Description
		Function to set a list of Windows Services as per Standard.Please refer document.
	#> 
    # Write-LogSectionHeader -Header "Configuring Services as per standard"
    Try
        {
            "dhcp,w32time".Split(",") | Foreach-Object {Set-Service $_ -startuptype "Automatic"}
            "WinHttpAutoProxySvc,wuauserv,BITS,ShellHWDetection".Split(",") | Foreach-Object {Set-Service $_ -startuptype "Manual"}
            "TrkWks,RpcLocator,RasMan,SCardSvr,SCPolicySvc,TapiSrv,DPS,ALG,CertPropSvc,AudioSrv,AudioEndpointBuilder,WerSvc,RasAuto".Split(",") | Foreach-Object {Set-Service $_ -startuptype "disabled"}
        }
    Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}

Function SetServerPowerScheme()
{
    <#	.Description
		Function to set Server Powersheme as per the best pracice
	#> 
    # Write-LogSectionHeader -Header "Configuring Server Power Scheme"
    Try
        {
    		powercfg.exe /SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
		    powercfg.exe /HIBERNATE off        
        }
    Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}

Function SetWindowsUpdateSettings()
{
    <#	.Description
		Function to set Windows Update settings to NOT automatically update and restart server.
	#> 
    # Write-LogSectionHeader -Header "Configuring Windows Update settings through Registry"
    Try
        {
            $wuRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            Set-ItemProperty -path $wuRegPath -Name AUOptions -value 1 -type DWord -Force
            Set-ItemProperty -path $wuRegPath -Name ScheduledInstallDay -value 0 -type DWord -Force
            Set-ItemProperty -path $wuRegPath -Name ScheduledInstallTime -value 3 -type DWord -Force
            Set-ItemProperty -path $wuRegPath -Name IncludeRecommendedUpdates -value 1 -type DWord -Force
            if(!(Test-Path -Path "$wuRegPath\Results\Detect")){New-Item -Path "$wuRegPath\Results\Detect" -Force}
            Set-ItemProperty -path $wuRegPath -Name LastError -value 2149859372 -type DWord -Force
            Set-ItemProperty -path $wuRegPath\Results\Detect -Name LastError -value 2149859372 -type DWord -Force
            Set-ItemProperty -path $wuRegPath\UAS -Name UpdateCount -value 0 -type DWord -Force
        }
    Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}

Function DisableWindowsErrReport()
{
    <#	.Description
		Function to disable Windows Error Reporting to Microsoft
	#>     
    # Write-LogSectionHeader -Header "Disabling Windows Error Reporting"
    Try
        {
            Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -value 1 -type DWord -Force
        }
        Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}  

Function SetVisualAffectReg()
{
    <#	.Description
		Function to set visual affects settings through registry
	#>     
    # Write-LogSectionHeader -Header "Setting Visual Affects Status Registry"
    Try
        {
            Set-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -value 2 -type DWord -Force
        }
        Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}

Function SetStandardReg()
{
    <#	.Description
        Function to set a list of registry entries as per standard.This includes certain Security related 
        settings too.Please refer WIN-RAD-XXXXXX document.
	#>     
    # Write-LogSectionHeader -Header "Setting Standard Registry values"
    Try
        {
            # Write-LogSectionHeader -Header "Setting MaxTokenSize Registry Value"
            Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters -Name MaxTokenSize -value 48000 -type DWord -Force

            # Write-LogSectionHeader -Header "Disabling SSL 2.0 , 3.0 and TLS 1.0,1.1,1.2 through Registry"
            $SSLRegPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
            if(!(Test-Path -Path "$SSLRegPath\SSL 2.0")){New-Item -Path "$SSLRegPath\SSL 2.0" -Force}
            if(!(Test-Path -Path "$SSLRegPath\SSL 2.0\Server")){New-Item -Path "$SSLRegPath\SSL 2.0\Server" -Force}
            Set-ItemProperty -path "$SSLRegPath\SSL 2.0\Server" -Name Enabled -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\SSL 2.0\Client")){New-Item -Path "$SSLRegPath\SSL 2.0\Client" -Force}
            Set-ItemProperty -path "$SSLRegPath\SSL 2.0\Client" -Name DisabledByDefault -value 1 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\SSL 3.0")){New-Item -Path "$SSLRegPath\SSL 3.0" -Force}
            if(!(Test-Path -Path "$SSLRegPath\SSL 3.0\Server")){New-Item -Path "$SSLRegPath\SSL 3.0\Server" -Force}
            Set-ItemProperty -path "$SSLRegPath\SSL 3.0\Server" -Name Enabled -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\SSL 3.0\Client")){New-Item -Path "$SSLRegPath\SSL 3.0\Client" -Force}
 
            Set-ItemProperty -path "$SSLRegPath\SSL 3.0\Client" -Name DisabledByDefault -value 1 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.0")){New-Item -Path "$SSLRegPath\TLS 1.0" -Force}
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.0\Server")){New-Item -Path "$SSLRegPath\TLS 1.0\Server" -Force}
            Set-ItemProperty -path "$SSLRegPath\TLS 1.0\Server" -Name Enabled -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.0\Client")){New-Item -Path "$SSLRegPath\TLS 1.0\Client" -Force}
            Set-ItemProperty -path "$SSLRegPath\TLS 1.0\Client" -Name Enabled -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.1")){New-Item -Path "$SSLRegPath\TLS 1.1" -Force}
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.1\Server")){New-Item -Path "$SSLRegPath\TLS 1.1\Server" -Force}
            Set-ItemProperty -path "$SSLRegPath\TLS 1.1\Server" -Name Enabled -value 1 -type DWord -Force
            Set-ItemProperty -path "$SSLRegPath\TLS 1.1\Server" -Name DisabledByDefault -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.1\Client")){New-Item -Path "$SSLRegPath\TLS 1.1\Client" -Force}
            Set-ItemProperty -path "$SSLRegPath\TLS 1.1\Client" -Name Enabled -value 1 -type DWord -Force
            Set-ItemProperty -path "$SSLRegPath\TLS 1.1\Client" -Name DisabledByDefault -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.2")){New-Item -Path "$SSLRegPath\TLS 1.2" -Force}
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.2\Server")){New-Item -Path "$SSLRegPath\TLS 1.2\Server" -Force}
            Set-ItemProperty -path "$SSLRegPath\TLS 1.2\Server" -Name Enabled -value 1 -type DWord -Force
            Set-ItemProperty -path "$SSLRegPath\TLS 1.2\Server" -Name DisabledByDefault -value 0 -type DWord -Force
            if(!(Test-Path -Path "$SSLRegPath\TLS 1.2\Client")){New-Item -Path "$SSLRegPath\TLS 1.2\Client" -Force}
            Set-ItemProperty -path "$SSLRegPath\TLS 1.2\Client" -Name Enabled -value 1 -type DWord -Force
            Set-ItemProperty -path "$SSLRegPath\TLS 1.2\Client" -Name DisabledByDefault -value 0 -type DWord -Force

            # Write-LogSectionHeader -Header "Modifying state of RDP-TCP security layer"
            Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -value 0 -type DWord -Force

            # Write-LogSectionHeader -Header "Disabling RC4 Cipher through Registry"
            $RC4RegPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
            @('RC4 40/128','RC4 56/128','RC4 128/128') | %{$key = (Get-Item HKLM:\).OpenSubKey($RC4RegPath, $true).CreateSubKey($_);$key.SetValue('Enabled', 0, 'DWord');$key.close()}

            # Write-LogSectionHeader -Header "New additional Security Settings changes for Windows 2016"
            new-item -Name Explorer -path "HKLM:\Software\Policies\Microsoft\Windows" -type Directory -Force
            set-itemproperty "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name NoAutoplayfornonVolume -type DWord -Value 0x00000001 -Force
            new-item -Name Personalization -path "HKLM:\Software\Policies\Microsoft\Windows" -type Directory -Force
            set-itemproperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenCamera -type DWord -Value 0x00000001 -Force
            set-itemproperty "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenSlideshow -type DWord -Value 0x00000001 -Force
            set-itemproperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutorun -type DWord -Value 0x00000001 -Force
            set-itemproperty "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name NTLMMinClientSec -type DWord -Value 0x20080000 -Force
            set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name MinEncryptionLevel -type DWord -Value 0x00000003 -Force
            set-itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCdm -type DWord -Value 0x00000001 -Force
            set-itemproperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature -type DWord -Value 0x00000001 -Force

            # Write-LogSectionHeader -Header "Limiting firewall log sizes"
            Set-NetFirewallProfile -name domain -LogMaxSizeKilobytes 32767 -LogAllowed false -LogBlocked true
            Set-NetFirewallProfile -name private -LogMaxSizeKilobytes 32767 -LogAllowed false -LogBlocked true
            Set-NetFirewallProfile -name public -LogMaxSizeKilobytes 32767 -LogAllowed false -LogBlocked true

            # Write-LogSectionHeader -Header "Disabling Dynamic DNS Update"
            Set-ItemProperty -path HKLM:\system\currentcontrolset\services\tcpip\parameters -Name DisableDynamicUpdate -Type DWORD -value 1
        }
    Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}

Function InstallWindowsRolesAndFeatures()
{
    <#	.Description
		Function to install Roles / Features as per requirements.Refer document.
    #>
    # Write-LogSectionHeader -Header "Installing Roles/Features as per standard"
    Try
        {
            install-WindowsFeature 'SNMP-Service'
            install-WindowsFeature 'RSAT-SNMP'
            install-WindowsFeature 'PowerShell-V2'
        }
    Catch
        {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        }
}

# Function CopyUnattendXMLFile()
# {
    # <#	.Description
		# Function to Copy Unattend.xml answer file for Sysprep.
    ##>
    # Write-LogSectionHeader -Header "Copying Unattend.xml file to use as Sysprep Answer File"
    # Try
        # {
            # if(Test-Path "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml"){
                # Remove-item -Path "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml" -recurse -Force
            # }
            # Invoke-WebRequest "http://40.1.228.100/AWS_REPO/GIS_IIHS_AWS_Windows_Build/AMI/" | Select-Object -ExpandProperty Links | Select-Object -ExpandProperty innerText | %{
                # $fName = $_
                # if($fName -eq 'Unattend.xml'){
                    # Write-LogSectionHeader -Header "Downloading Unattend.xml from http://40.1.228.100/AWS_REPO/GIS_IIHS_AWS_Windows_Build/AMI/$fName to C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep"
                    # (New-Object System.Net.WebClient).DownloadFile("http://40.1.228.100/AWS_REPO/GIS_IIHS_AWS_Windows_Build/AMI/$fName", "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml")
                    # while(!(Test-Path "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml")){
                        # Start-Sleep -Seconds 5
                    # }
                # }
            # }
        # }
    # Catch
        # {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        # }
# }

# Function CopyBuildScripts()
# {
    # <#	.Description
		# Function to Copy latest Build script which will be used during configuring deployed EC2 instance
    ##>
    # Write-LogSectionHeader -Header "Copying latest Build Script files"
    # Try
        # {
            # Invoke-WebRequest "http://40.1.228.100/AWS_REPO/GIS_IIHS_AWS_Windows_Build/Deploy/" | Select-Object -ExpandProperty Links | Select-Object -ExpandProperty innerText | %{
                # $fName = $_
                # if($fName -like '*.*'){
                    # Write-LogSectionHeader -Header "Downloading $fName from http://40.1.228.100/AWS_REPO/GIS_IIHS_AWS_Windows_Build/Deploy/$fName to C:\Build\"
                    # (New-Object System.Net.WebClient).DownloadFile("http://40.1.228.100/AWS_REPO/GIS_IIHS_AWS_Windows_Build/Deploy/$fName", "C:\Build\$fName")
                    # while(!(Test-Path "C:\Build\$fName")){
                        # Start-Sleep -Seconds 5
                    # }
                # }
            # }
        # }
    # Catch
        # {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        # }
# }


# Function CopyPatch()
# {
    # <#	.Description
		# Function to create a Folder to store new patches for Windows 2016. Download patches from Web Server.
    ##>
    # Write-LogSectionHeader -Header "Createing a new Folder to store Windows 2016 patches if it doesn't exist already"
    # Try
        # {
            # if(Test-Path $Global:buildPath\Patches\Windows2016){
                # Remove-item -Path $Global:buildPath\Patches\Windows2016\* -recurse -Force
            # }
            # else{
                # New-Item $Global:buildPath\Patches\Windows2016 -Type Directory -Force
            # }
            # Write-LogSectionHeader -Header "Copying Patches if any patch available to be installed in the AMI"
            # Invoke-WebRequest "http://40.1.228.100/AWS_REPO/Patches/" | Select-Object -ExpandProperty Links | Select-Object -ExpandProperty innerText | %{
                # $fName = $_
                # if($fName -like '*.msu' -or $fName -like '*.exe'){
                    # Write-LogSectionHeader -Header "Downloading Patch from http://40.1.228.100/AWS_REPO/Patches/$fName to $Global:buildPath\Patches\Windows2016"
                    # (New-Object System.Net.WebClient).DownloadFile("http://40.1.228.100/AWS_REPO/Patches/$fName", "$Global:buildPath\Patches\Windows2016\$fName")
                    # while(!(Test-Path "C:\build\Patches\Windows2016\$fName")){
                        # Start-Sleep -Seconds 5
                    # }
                # }
            # }
        # }
    # Catch
        # {
            # "An error occurred: $_" | Out-File $Global:sFullPath -append; Continue
        # }
# }

# Function InstallPatch()
# {
	# <#	.Description
		# Function to install Windows Updates on the Packer Builder Temp EC2
	##>    
	# Try{
        ##Checking if new patches available in the source Patch Directory path
        # if((Get-ChildItem "$Global:buildPath\Patches\Windows2016" | Measure-Object).Count -eq 0)
        # {
            # Write-LogSectionHeader -Header "No patche to be installed this time.Moving on"
        # }
        # else{
            # Write-LogSectionHeader -Header "Patch(s) found in the Folder.Installation will start"
            # Write-LogSectionHeader -Header "Starting Windows Patch installation"
            # $Count = 1
            # Get-ChildItem $Global:buildPath\Patches\Windows2016 | where{$_.PSIsContainer -eq $False } | %{
                # $pFileName = $_.Name
                # $patchFilePath = "$Global:buildPath\Patches\Windows2016\$pFileName"            
                # Write-LogSectionHeader -Header "$Count)Installing Patch : $pFileName"                
                # if($pFileName -like "*.msu*"){
                    # $install = [System.Diagnostics.Process]::Start( "wusa.exe","$patchFilePath /quiet /norestart")
                    # $install | Out-File $Global:sFullPath  -append
                    # $install.WaitForExit()				
                # }
                # elseif($pFileName -like "*.exe*"){
                    # cmd /c $patchFilePath /q /norestart /wait
                # } 
                # else{
                    # Write-LogSectionHeader -Header "Patch type is not recognized. Patch will not be installed"
                # }                      
                # $Count++
            # }  
            # Write-LogSectionHeader -Header "Windows Patch installation completed"
        # }
        # Start-Sleep -Seconds 600
	# }
	# Catch{"An error occurred: $_" | Out-File $Global:sFullPath  -append; Continue}
# }

# This section call all functions written above. While calling functions, make sure, sequence are set properly.Otherwise it may create issues.
SetService
SetServerPowerScheme
SetWindowsUpdateSettings
DisableWindowsErrReport
SetStandardReg
InstallWindowsRolesAndFeatures
# CopyUnattendXMLFile
# CopyBuildScripts
#CopyPatch
#InstallPatch
# Stop-Transcript
Exit