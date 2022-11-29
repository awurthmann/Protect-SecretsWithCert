#powershell.exe


# Written by: Aaron Wurthmann
#
# You the executor, runner, user accept all liability.
# This code comes with ABSOLUTELY NO WARRANTY.
# This is free and unencumbered software released into the public domain.
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# --------------------------------------------------------------------------------------------
# Name: Protect-SecretsWithCert.ps1
# Version: 2022.11.29.1057
# Description: 
#	This script is a collection of functions that can be used to obfuscate passwords and secrets Public, Private certificate key pairs.
#	It is purposefully written without a lot of additional error detection. Relying instead on the existing commands.
#	In this use case different users on the same local system need access to the secret(s).
#
# Tested with: Microsoft Windows [Version 10.0.22000.0], PowerShell [5.1.22000.832]
#	NOTE: Windows version 10.0.22000 is Windows 11
#	"Microsoft Windows [Version $([System.Environment]::OSVersion.Version)], PowerShell [$($PSVersionTable.PSVersion.ToString())]"
#

### Functions
## Check if Admin Function##
function isAdmin {
	# Checks if the current user has "Administrator" privileges, returns True or False 
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
## End Check if Admin Function##

## Create Self Signed Certificate Function
function New-SelfSignedSecretsCertificate {
	# Creates self signed certificate in provided store location or default LocalMachine\My
	Param(
		[Parameter(Position=0, Mandatory=$true)][string]$certName,
		[Parameter(Position=1, Mandatory=$false)][string]$certStorePath = "cert:\LocalMachine\My"
	)
	
	If (($certStorePath -like "cert:\LocalMachine\*") -and (!(isAdmin))) {
		Write-Error -Message "Administrative privileges are required to create a certificate in '$certStorePath' " -Category PermissionDenied -ErrorAction Stop
		return
	}
	
	try {
		New-SelfSignedCertificate -Subject $certName -CertStoreLocation "cert:\LocalMachine\My" -KeyUsage KeyEncipherment,DataEncipherment, KeyAgreement -Type DocumentEncryptionCert
	}
	catch{
		#Write-Log $ErrorLogFile "ERROR: $($_.Exception.Message)"
		#Use line above to catch errors into an error log.
		throw $_
	}
	
}
## End Create Self Signed Certificate Function

## Get Self Signed Certificate Function
function Get-SelfSignedSecretsCertificate {
	Param(
		[Parameter(Position=0, Mandatory=$true)][string]$certStorePath,
		[Parameter(Position=1, Mandatory=$false)][string]$certName,
		[Parameter(Position=1, Mandatory=$false)][string]$certThumbprint
	)
	
	If ((!($certName)) -and (!($certThumbprint))) {
		Write-Error -Message "Must specify a certificate name (CertName) or thumbprint (certThumbprint)" -Category InvalidArgument -ErrorAction Stop
		return
	}
	
	try {
		If ($certName){
			$Cert = Get-ChildItem $certStorePath | Where-Object {$_.Subject -like "CN=$certName*"}
		}
		
		If ($certThumbprint){
			$Cert = Get-ChildItem $certStorePath | Where-Object {$_.Thumbprint -eq $certThumbprint}
		}
	}
	catch {
		#Write-Log $ErrorLogFile "ERROR: $($_.Exception.Message)"
		#Use line above to catch errors into an error log.
		throw $_
	}
	
	return $Cert
}
## End Get Self Signed Certificate Function

## Edit Self Signed Certificate Permissions Function
function Edit-CertificatePermissions {
	Param(
		[Parameter(Position=0, Mandatory=$true)]$Cert,
		[Parameter(Position=1, Mandatory=$false)][string]$User = "NT AUTHORITY\Authenticated Users",
		[Parameter(Position=2, Mandatory=$false)][string]$Permission = "Read"
	)
	
	If ($($Cert.PSParentPath.Split(':')[-1].Split('\')[0]) -eq "LocalMachine") {
		If (!(isAdmin)) {
			Write-Error -Message "Administrative privileges are required to edit a certificate in '$($Cert.PSParentPath.Split(':')[-1].Split('\')[0])' " -Category PermissionDenied -ErrorAction Stop
			return
		}
		
		$certFolder="$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys"
		
	}
	ElseIf ($($Cert.PSParentPath.Split(':')[-1].Split('\')[0]) -eq "CurrentUser") {
		$certFolder="$env:APPDATA\Microsoft\Crypto\Keys"
	}
	
	try{
		$rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
		$fileName = $rsaCert.key.UniqueName
		$certFilePath = "$certFolder\$fileName"
	}
	catch {
		#Write-Log $ErrorLogFile "ERROR: $($_.Exception.Message)"
		#Use line above to catch errors into an error log.
		throw $_
	}
	
	If (Test-Path $certFilePath) {
		try {
			$Rule = new-object security.accesscontrol.filesystemaccessrule $User, $Permission, allow
			$Permissions = Get-Acl -Path $certFilePath
			$Permissions.AddAccessRule($Rule)
			Set-Acl -Path $certFilePath -AclObject $Permissions
		}
		catch {
			#Write-Log $ErrorLogFile "ERROR: $($_.Exception.Message)"
			#Use line above to catch errors into an error log.
			throw $_
		}
	}
	Else {
		Write-Error -Message "File '$certFilePath' not found " -Category ObjectNotFound -ErrorAction Stop
		return
	}

}
## End Edit Self Signed Certificate Permissions Function

## Encrypt String with Certificate
function Protect-SecretWithCert {
	Param(
		[Parameter(Position=0, Mandatory=$true)]$Cert,
		[Parameter(Position=1, Mandatory=$true)][string]$PlainTextString
	)
	
	try {
		$EncryptedBlock = $PlainTextString | Protect-CmsMessage -To $Cert.Subject
	}
	catch {
		#Write-Log $ErrorLogFile "ERROR: $($_.Exception.Message)"
		#Use line above to catch errors into an error log.
		throw $_
	}
	return $EncryptedBlock
}
## End Encrypt String with Certificate

## Decrypt String with Certificate
function Unprotect-SecretWithCert {
	Param(
		[Parameter(Position=0, Mandatory=$true)]$EncryptedBlock
	)
	
	try {
		$PlainTextString = Unprotect-CmsMessage -Content $EncryptedBlock
	}
	catch {
		#Write-Log $ErrorLogFile "ERROR: $($_.Exception.Message)"
		#Use line above to catch errors into an error log.
		throw $_
	}
	return $PlainTextString
}
## End Decrypt String with Certificate
### End Functions



### EXAMPLE USAGE

# Setup Example
# Admin permissions are needed to create and edit a certificate in the LocalMachine key store.
# Ideally you want to limit the permissions down to only the users or groups that need to decrypt.
#	The default and the example is 'Authenticated Users'. 
New-SelfSignedSecretsCertificate -certName "PowerShell Automation" -certStorePath "cert:\LocalMachine\My"
$myCert=Get-SelfSignedSecretsCertificate -certStorePath "cert:\LocalMachine\My" -certName "PowerShell Automation"
Edit-CertificatePermissions -Cert $myCert -User "NT AUTHORITY\Authenticated Users" -Permission "Read"
# End Setup Example

# Encrypt Example
# Need to get certificate (Cert.Subject) prior to encrypt.
# Admin privs are not needed to encrypt or decrypt, read permissions to the certificates Private key are neede. See above/Edit-CertificatePermissions
# OutFile used in example. IRL the Encrypted Response may go into a CSV, database, etc
# If you do intend to store the encrypted response in a single file just use native Protect-CmsMessage. e.g. $PlainTextString | Protect-CmsMessage -To $Cert.Subject 
$myCert=Get-SelfSignedSecretsCertificate -certStorePath "cert:\LocalMachine\My" -certName "PowerShell Automation"
$EncryptedResponse = Protect-SecretWithCert -Cert $myCert -PlainTextString "This is my secret message"
$EncryptedResponse | Out-File .\Example-Encrypted-Response.txt
# End Encrypt Example

# Decrypt Example
# Do NOT need get the certificate ahead of decrypting 
# Admin privs are not needed to encrypt or decrypt, read permissions to the certificates Private key are neede. See above/Edit-CertificatePermissions
# Get content from file as a string (it HAS TO BE a string) and print plain text to standard out. IRL you'd likely retrieve the Encrypted Block from a CSV or database
# If you do intend to read the encrypted response from a single file just use native Unprotect-CmsMessage. e.g. Unprotect-CmsMessage -Path .\Example-Encrypted-Response.txt
[string]$myEncryptedBlock = Get-Content .\Example-Encrypted-Response.txt
$PlainTextResponse = Unprotect-SecretWithCert -EncryptedBlock $myEncryptedBlock
Write-Host $PlainTextResponse
Clear-Variable PlainTextResponse -Force -ErrorAction SilentlyContinue
## Always clear the plain text variable after its use is complete 
# End Decrypt Example

### END EXAMPLE USAGE