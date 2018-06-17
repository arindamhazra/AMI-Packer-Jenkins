<#	.Description
    This script is intended to be used to automate Packer AMI creation for Windows. This scrips assumes you have an IAM 
    user already available with all requires roles to create and test AMI in different AWS Accounts.
    Make sure, you have AWS credentials configured under <user profile>\.aws\credentials location.

	.INPUTS
    Once script launched, it will ask you a series of questions and some option selections before creating the 
    AMI for you. Read each question thoroughly before making a selection.
    Make sure, you have a Change Request logged in ServiceNow before you start the AMI creation process.  
    Following Prerequisites should be in place before executing this script:
    a)AWS Profile for 'saml' or the IAM user created at <user profile>\.aws\Credentials
    b)NO_PROXY,HTTP_PROXY & HTTPS_PROXY set as per requirement.Refer Packer.io documentation
    c)Packer.exe copied in to C:\Windows\System32 Directory
    d)PACKER_LOG and PACKER_LOG_PATH Environment Variables set properly for debug logging
 
	.Example
	.\packer.ps1

	.Example
	None (Refer iihs-windows-2016.json)

	.Outputs
	Logging to sessoin and written to <invocation drive>\AWS_REPO\PackerLogs\Windows_AMI_Creation.log (the Script Execution log file)
    Logging Script Transcript to <invocation drive>\AWS_REPO\PackerLogs\Packer_Builder_Transcript_Log.log (the Transcript log file)
    Logging Core Packer debug logs to <invocation drive>\AWS_REPO\PackerLogs\packerlog.txt (the Packer Debug log file)
    
    
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
$Global:rootDrive = (Get-Item (Split-Path -Parent -Path $MyInvocation.MyCommand.Definition)).Root
$Global:rootPath = "${Global:rootDrive}"
$Global:packerPath = Join-Path $Global:rootPath "AMI-Packer-Jenkins\AMI"
$Global:strLogDateTimeFormat = "dd-MMM-yyyy HH:mm:ss"
$Global:jsonTemplateFile = Join-Path $Global:packerPath "Template.json"
$Global:userDataPath = (Join-Path $Global:packerPath "userdata.txt").Replace("\","\\")
$Global:provisonerPath = (Join-Path $Global:packerPath "ami_config.ps1").Replace("\","\\")
$Global:regionName = $Global:sourceAMIId = $Global:chgNo = ""
$Global:awsProfileName = "ss"
$Global:securityGroup = $env:PRI_SECURITYGROUP
$Global:vpcId = $env:PRI_VPCID
$Global:subnetId = $env:PRI_SUBNETID
$Global:AWSAccessKey = $env:PRI_AWS_ACCESS_KEY_ID
$Global:AWSSecretKey = $env:PRI_AWS_SECRET_ACCESS_KEY
$Global:sourceAMIId = $env:PRI_AMIID
$Global:regionName = "us-east-2"


if(Test-Path $Global:jsonTemplateFile){Remove-item $Global:jsonTemplateFile -Force}

$Global:chgNo = "CHG12345"
$amiDate = $((Get-Date).ToString("yyyyMMdd"))
$amiTime = $((Get-Date).ToString("HHmm"))
$newAMIName = "WIN2016-Standard-NonEncrypted-V"+$amiDate+"_"+$amiTime
$createdBy = $env:USERNAME


Function Create-Packer-AMI(){
Try{
   	<#	.Description
		Function to create Packer AMI for AWS
	#>
	powershell "$Global:packerPath\Packer.exe" build $Global:jsonTemplateFile

}
Catch
{
	Write-Host "ERROR : $_" -Foregroundcolor Yellow

}
}

Function Create_JSON_Template($region,$sAMI,$chg){
Try{	
   	<#	.Description
		Function to generate a Template JSON file to be used by Packer Builder
        	"security_group": "$Global:securityGroup",
        	"subnet_id": "$Global:subnetId",
		"vpc_id": "$Global:vpcId",
            	"vpc_id": "{{user ``vpc_id``}}",
            	"subnet_id": "{{user ``subnet_id``}}",
		"security_group_id": "{{user ``security_group``}}",
	#> 
$input = @"
{
	"variables": {
		"aws_ami": "$Global:sourceAMIId",
		"access_key": "$Global:AWSAccessKey",
		"secret_key": "$Global:AWSSecretKey",
        	"security_group": "$Global:securityGroup",
        	"subnet_id": "$Global:subnetId",
		"vpc_id": "$Global:vpcId",
		"change_request": "$Global:chgNo",
		"region_name": "$Global:regionName",
        	"new_aws_ami": "$newAMIName",
        	"created_by": "$createdBy"
	},
    "builders": [
        {
            	"type": "amazon-ebs",
            	"access_key": "{{user ``access_key``}}",
	    	"secret_key": "{{user ``secret_key``}}",
            	"vpc_id": "{{user ``vpc_id``}}",
            	"subnet_id": "{{user ``subnet_id``}}",
		"security_group_id": "{{user ``security_group``}}",
           	"region": "{{user ``region_name``}}",
            	"source_ami": "{{user ``aws_ami``}}",
            	"instance_type": "t2.micro",
            	"ami_description": "Windows 2016 AMI - Created on {{timestamp}}",
            	"disable_stop_instance": "false",            
            	"launch_block_device_mappings": [
                	{
                    	"device_name": "/dev/sda1",
                    	"volume_type": "gp2",
                    	"delete_on_termination": true
                	}
            	],
	        "run_tags": {
                "ApplicationCi": "HOME Windows AMI",
                "CNAME": "PBuilder",
                "Name": "Packer Builder",
                "CostCenter": "ABCD1234",
                "OsType": "Windows",
                "DataClassification": "Green",
                "Hipaa": "No",
                "Level1BusinessArea": "IT",
                "PrimaryItContact": "Arindam",
                "SystemCustodian": "Adhyayan",
                "SystemOwner": "Adhyayan",
                "SnowRequestId": "{{user ``change_request``}}"
            },
            "tags": {
                "OSVersion": "Windows Server 2016",
                "Release": "Latest",
                "CreatedBy": "{{user ``created_by``}}",
                "BaseImage": "{{user ``aws_ami``}}",
                "ChangeRequest": "{{user ``change_request``}}",
                "Name": "WIN2016-Standard-NonEncrypted-Current",
                "Company": "Arindam Home Company"
              },          
            "ami_name": "{{user ``new_aws_ami``}}",
            "user_data_file": "$Global:userDataPath",
            "communicator": "winrm",
            "winrm_username": "Administrator",
            "winrm_password": "abcd@1234",
            "winrm_timeout": "30m"
        }
    ],
    "provisioners": [
    {
      "type": "powershell",
      "elevated_user": "Administrator",
      "elevated_password": "abcd@1234",      
      "script": "$Global:provisonerPath"      
    },
    {
        "type": "windows-restart",
        "restart_timeout": "30m"
    },   
    {
        "type": "powershell",
        "inline": [
			"C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Scripts\\InitializeInstance.ps1 -Schedule",	
			"C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Scripts\\SysprepInstance.ps1 -NoShutdown"
        ]
    }
    ]
}	
"@ 
$input | Out-File $Global:jsonTemplateFile -Encoding ascii -append
}
Catch
{
	"An error occurred: $_" | Out-File $Global:packerLogFilePath -append; Exit
}
}

Create_JSON_Template $Global:regionName $Global:sourceAMIId $Global:chgNo

if(!(Test-Path $Global:jsonTemplateFile)){ 
	Write-Host "ERROR: Template creation Failed.Please try manually..." -Foregroundcolor Yellow	
	Exit
}
else{
	if(!(powershell "$Global:packerPath\Packer.exe" validate $Global:jsonTemplateFile | Select-String("Template validation failed"))){
		Write-Host "Template is Valid.Script will proceed now" -Foregroundcolor Green
	}
	else{
		Write-Host "ERROR: Template is InValid.Please check the JSON Template.Packer will exit now" -Foregroundcolor Yello
		Exit
	}
}

Create-Packer-AMI
Exit