################################################################################################################
# Name: Module-vCloud-Extender.psm1
# Date: 21/05/2018 (v0.1)
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
#
# Purpose: PowerShell modules to expose API functions for vCloud Extender v1.1 via PowerShell.
#
# WARNING: This work is all derived from monitoring API calls between UI and the service and guessing operations
# based on other VMWare APIs. There is no public documentation on the API available so be aware that this is a
# hack. This has been designed for lab work only and you should always test yourself extensively before deploying
# in Production. 
#
# Tested on vCloud Extender v1.0, 1.1, v1.1.0.1 GA
################################################################################################################
# Change Log
# v0.1 - Inital Release (Alpha) 21/05/2018
# - Created functions for authentication with the CX Cloud Service
# - Created functions for API CRUD Operations
# - Created basic management and configuration functions for a CX Cloud Service deployment
# - Created functions for basic Certificate Chain and Certificate Trust Store Operations
# v0.2 - Updated functions for CCM/CCE activation for Public Release
################################################################################################################
# To Do:
# 1. Add handlers for 204 Return codes for GET methods in API
# 2. Add documentation for all methods (currently only basic)
# 3. Develop methods for all client-side operations
# 4. Convert to SecureStrings all the passwords
################################################################################################################
### Ignore TLS/SSL errors and set to TLS 1.2
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region: Support-Functions
function Get-SHA2CertificateThumbprint(){
    <#
    .SYNOPSIS
    Function to calculate the SHA256 Thumbprint of a provided PEM Certificate.

    .DESCRIPTION
    Function to calculate the SHA256 Thumbprint of a provided PEM Certificate.

    .PARAMETER PEMCertificate
    A PEM encoded Certificate (loaded as a string)

    .EXAMPLE
    Get-SHA2CertificateThumbprint -PEMCertificate (Get-Content D:\vcdextender.crt | Out-string)

    Returns the SHA-256 Thumbprint for the Certificate in file D:\vcdextender.crt
    #>
    Param(
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $PEMCertificate
    )
    # Need to save the Certificate as a file and load the Certificate using the primateive and extract the certificate data
    Out-File -InputObject $PEMCertificate -FilePath "TempCertificate.pem" -Force
    $PEMCertificateRaw = Get-PfxCertificate "TempCertificate.pem"

    [Byte[]] $certificateBytes = $PEMCertificateRaw.GetRawCertData()

    # Now use the SHA256 Provider to Calculate the Hash and format it in the require format
    $objSHA256Provider = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $byteHash = $objSHA256Provider.ComputeHash($certificateBytes)
    [string]$strCertificateHash = [BitConverter]::Tostring($byteHash) -replace '[^0-9a-f]'
    $strCertificateHash = $strCertificateHash -replace '(..(?!$))','$1:'
    $strCertificateHash
    Remove-Item -Path "TempCertificate.pem" -Force -Confirm:$false
}

function Test-ValidIPString(){
	<#
	.SYNOPSIS
	 This cmdlet returns true if a provided string matches a valid pattern for a single IP

	.DESCRIPTION
	 This cmdlet returns true if a provided string matches a valid pattern for a single IP

 	.PARAMETER IPAddress
	The IP address to test against

	.EXAMPLE
	Test-ValidIPString "10.10.0.0"
	Returns a true as the provided value is in the correct format

	.NOTES
	  NAME: Test-ValidIPString
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-10-06
	  STATE: Alpha (Testing)
	 #>
	Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
			[ValidateNotNullorEmpty()] [string[]] $IPAddress
	)
	[bool] $boolValid = $true
	foreach($objIP in $IPAddress){
		if(!($objIP -match "([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")){
			$boolValid = $false
		}
	}
	$boolValid
}

#endregion

#region: Common-API-Methods-Mobility-Service
function Connect-CXService(){
	<#
	.SYNOPSIS
	 This cmdlet establishes a connection to the REST API of a Mobility Service (CX Cloud Service or CX Cloud Connector) and caches the credentials or a session token

	.DESCRIPTION
     This cmdlet establishes a connection to the REST API of a Mobility Service (CX Cloud Service or CX Cloud Connector) and caches the credentials or a session token. The service allows two authentication methods; Local and vCenter SSO.

     If Local authentication is used the credentials need to be sent in Plain-Text for every API call (which is not ideal). if vCenter SSO authentication is used a Session Token can be used for subsiquent API calls.

	.PARAMETER Server
	Specifies the IP address or Hostname of the Mobility Service Server

	.PARAMETER Port
	Specifies the TCP Port for the connection; the Default is TCP 443 (Authenticated)

	.PARAMETER Credentials
	Specifies a PSCredential object that contains credentials for authenticating with the server. NOTE: The username is also case-sensative (eg. administrator)

    .PARAMETER AuthProvider
    The Authentication Provider which should be used to connect (Local or SSO). The default is Local authentication

	.EXAMPLE
	Connect-CXService -Server "vcdextender.pigeonnuggets.com"

	Connects to the Cloud Mobility Service (CX Cloud Service) server at https://vcdextender.pigeonnuggets.com:443 and prompts for Credentials

	.EXAMPLE
	Connect-CXService -Server "vcdextender.pigeonnuggets.com" -Credentials $Cred

   	Connects to the Cloud Mobility Service (CX Cloud Service) server at https://vcdextender.pigeonnuggets.com:443 using the Credentials in the PSCredential object $Cred

	.EXAMPLE
	Connect-CXService -Server "vcdextender.pigeonnuggets.com" -Credentials $Cred -Port 19821

    Connects to the Cloud Mobility Service (CX Cloud Service) server at https://vcdextender.pigeonnuggets.com:19821 using the Credentials in the PSCredential object $Cred

	.NOTES
	  NAME: Connect-CXService
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-05-06
	  STATE: Alpha (Testing)
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Server,
        [Parameter(Mandatory=$False)]
            [ValidateSet("Local","SSO")]  [string] $AuthProvider="Local",
        [Parameter(Mandatory=$False)]
			[ValidateRange(1,65536)] [int] $Port=443,
		[Parameter(Mandatory=$True)] [PSCredential] $Credentials = $Host.ui.PromptForCredential("Enter credentials for $Server", "Please enter your user name and password for the CX Cloud Service/CX Connector Service.", "", "")
    )
    # TO DO: Check if already connected and warn if already connected to a server
	if($global:DefaultCXServer.IsConnected){
        Write-Warning "You are currently already connected to the CX Service $($global:DefaultCXServer.Server). Your existing session will be disconnected if you continue." -WarningAction Inquire
        Disconnect-CXService
    }
    # Attempt to connect to the CX Cloud Service and return the deployment info
    [string] $InfoURI = "https://" + $Server + ":" + $Port + "/mobility/info"
    $InfoHeaders = @{
        'Accept' = 'application/json'
	}
	try{
		$JSONDeploymentInfoRequest = (Invoke-WebRequest -Uri $InfoURI -Method Get -Headers $InfoHeaders) | ConvertFrom-Json
	} catch {
		throw "A connection to the Mobility Service for $Server was unsuccessful. Please check the Server Name and Port and that the Server is currently online."
	}
   # Next we need to create the header for an authentication request to check if the provided credentials are valid
   [string] $authToken = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Credentials.UserName+':'+$Credentials.GetNetworkCredential().Password))
   if($AuthProvider -eq "Local"){
        $URIHeaders = @{
            'Authorization' = "Basic $authToken"
            'Content-Type' = "application/json"
            'x-mobility-authenticator' = "LOCAL_MACHINE"
        }
   } elseif($AuthProvider -eq "SSO"){
        $URIHeaders = @{
            'Authorization' = "Basic $authToken"
            'Content-Type' = "application/json"
            'x-mobility-authenticator' = "VCENTER"
        }
   }
   # Now make the call to the Logon Service
   [string] $AuthURI = "https://" + $Server + ":" + $Port + "/mobility/mgmt/login"
   try{
        $JSONAuthRequest = Invoke-WebRequest -Uri $AuthURI -Method Get -Headers $URIHeaders
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized"){
            throw "An error occured connecting to $AuthURI with the provided credentials. Please check the Server Name, Port and Credentials"
        }
    }

    # If 204 No Content is returned Authentication has succeeded; set the variables
    $objCXService = New-Object System.Management.Automation.PSObject
	$objCXService | Add-Member Note* Name $Server
	$objCXService | Add-Member Note* ServiceURI ("https://" + $Server + ":" + $Port + "/mobility")
	$objCXService | Add-Member Note* Port $Port
	$objCXService | Add-Member Note* User $Credentials.UserName
	$objCXService | Add-Member Note* AuthenticationProvider $AuthProvider
    if($AuthProvider -eq "SSO"){
        $objCXService | Add-Member Note* AccessToken $JSONAuthRequest.Headers.'x-mobility-authorization'
    } elseif($AuthProvider -eq "Local"){
        $objCXService | Add-Member Note* AccessToken "Basic $authToken"
    }
    $objCXService | Add-Member Note* DeploymentType $JSONDeploymentInfoRequest.deploymentType
    $objCXService | Add-Member Note* DeploymentEnvironment $JSONDeploymentInfoRequest.deploymentEnv
    $objCXService | Add-Member Note* Version $JSONDeploymentInfoRequest.version
    $objCXService | Add-Member Note* DatabaseUri $JSONDeploymentInfoRequest.dbUrl
    $objCXService | Add-Member Note* IsConnected $true
	Set-Variable -Name "DefaultCXServer" -Value $objCXService -Scope Global
}

function Disconnect-CXService(){
	<#
	.SYNOPSIS
	 This cmdlet disconnects the session from the connected CX Service.

	.DESCRIPTION
	 This cmdlet disconnects the session from the connected CX Service.

	.EXAMPLE
	 Disconnect-CXService

	 Disconnects/ends the currently connected session to the CX Service.

	.NOTES
	  NAME: Disconnect-CXService
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-05-06
	#>
	Set-Variable -Name "DefaultCXServer" -Value $null -Scope Global
}

function Test-CXServiceEnvironment(){
	<#
	.SYNOPSIS
	Performs some basic checks against the currently connected CX Service to determine if the current version is
	greater than the required version by a cmdlet and that there is a current connection active.

	.DESCRIPTION
	Performs some basic checks against the currently connected CX Service to determine if the current version is
    greater than the required version by a cmdlet and that there is a current connection active.

	Returns true if the test passes

	.PARAMETER Version
    The Minimum Version required by the cmdlet.

    .PARAMETER RequiredDeploymentType
    The CX Deployment Type (cx-cloud-service or cx-cloud-connector)

	.EXAMPLE
	Test-CXServiceEnvironment -Version 1.00
	Will return true if connected to a CX Service with a Version greater then "1.00"

	.EXAMPLE
	Test-CXServiceEnvironment
    Will return true if connected to a CX Server (any version).

    .EXAMPLE
	Test-CXServiceEnvironment -RequiredDeploymentType "cx-cloud-connector"
    Will return true if connected CX Server is of type CX Cloud Connector (on-premise component)


    .EXAMPLE
	Test-CXServiceEnvironment -RequiredDeploymentType "cx-cloud-service"
    Will return true if connected CX Server is of type CX Cloud Service (provider side component)

	.NOTES
	  NAME: Test-CXServiceEnvironment
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-05-06
	#>
	Param(
		[Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [double] $Version,
        [Parameter(Mandatory=$False)]
            [ValidateSet("cx-cloud-service","cx-connector")] [string] $RequiredDeploymentType
	)
	if(!$global:DefaultCXServer.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-CXService cmdlet."
		$false
		Break
	} elseif((!([string]::IsNullOrEmpty($Version))) -and (!($global:DefaultCXServer.Version -gt $Version))){
		throw "The executing cmdlet requires the vCloud Extender environment to be greater then $Version. The version of the connected server is $($global:DefaultCXServer.Version)"
		$false
		Break
    } elseif((!([string]::IsNullOrEmpty($RequiredDeploymentType))) -and ($RequiredDeploymentType -ne $global:DefaultCXServer.DeploymentType)){
        throw "The executing cmdlet is not supported on the current deployment type: $($global:DefaultCXServer.DeploymentType)"
        $False
        Break
    } else {
		$true
	}
}

function Out-CXServiceAuthenticationHeader(){
    <#
    .SYNOPSIS
	Creates the required HTTP Headers for the API calls based on the authentication method.

	.DESCRIPTION
	Creates the required HTTP Headers for the API calls based on the authentication method.

    .EXAMPLE
    Out-CXServiceAuthenticationHeader

    Returns a well formed set of headers for authentication against the API

    .NOTES
	  NAME: Out-CXServiceAuthenticationHeader
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-05-06
	#>
    # Check if vCenter SSO or Local Authentication is being used
    if($global:DefaultCXServer.AuthenticationProvider -eq "SSO"){
        $URIHeaders = @{
            'Authorization' = "$($global:DefaultCXServer.AccessToken)"
            'Content-Type' = "application/json"
            'x-mobility-authenticator' = "VCENTER"
            'x-mobility-userName' = "$($global:DefaultCXServer.User)"
        }
    } elseif($global:DefaultCXServer.AuthenticationProvider -eq "Local"){
        $URIHeaders = @{
            'Authorization' = "$($global:DefaultCXServer.AccessToken)"
            'Content-Type' = "application/json"
            'x-mobility-authenticator' = "LOCAL_MACHINE"
        }
    }
    # Return the correct header for the request
    $URIHeaders
}

function Invoke-CXServiceAPIGet(){
	<#
	.SYNOPSIS
	Wrapper function which returns the JSON response from a vCloud Extender (CX Service) API Call.

	.DESCRIPTION
	Wrapper function which returns the JSON response from a vCloud Extender (CX Service) API Call.

	.PARAMETER URI
	The URI of the vCloud Extender API object to perform the GET request against

	.EXAMPLE
	Invoke-CXServiceAPIGet -URI "https://vcdextender.pigeonnuggets.com/mobility/mgmt/vc/"

	Returns the JSON response from a HTTP GET to the /mobility/mgmt/vc/ API call using the connection attributes from the current connection

	.NOTES
	  NAME: Invoke-CXServiceAPIGet
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-06
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI
    )
    # First check if there is a connection to the service
    if(!(Test-CXServiceEnvironment)){
		Break
	}
    # Setup Authentication Headers for the API call to retireve the data from CX Service
    $AuthenticationHeaders = Out-CXServiceAuthenticationHeader
	try{
        $Request = Invoke-WebRequest -Uri $URI -Method Get -Headers $AuthenticationHeaders
        if($Request.Content -ne $null){
            ConvertFrom-Json $Request.Content
        }
	} catch {
		throw "An error occured attempting to make HTTP GET against $URI"
	}
}

function Invoke-CXServiceAPIPut(){
	<#
	.SYNOPSIS
    Wrapper function which performs a HTTP PUT of a JSON payload to the currently connected vCloud Extender (CX Service) API Service.

	.DESCRIPTION
	Wrapper function which performs a HTTP PUT of a JSON payload to the currently connected vCloud Extender (CX Service) API Service.

	.PARAMETER URI
    The URI to make the API PUT Request against

    .PARAMETER Data
    JSON Payload to PUT to the API URI

    .EXAMPLE
    Invoke-CXServiceAPIPut -Uri "https://vcdextender.pigeonnuggets.com/mgmt/security/certificatechain" -Data ($objCertificateChain | ConvertTo-JSON)

    Performs a HTTP PUT request against https://vcdextender.pigeonnuggets.com/mgmt/security/certificatechain with the JSON payload in the object $objCertificateChain

    .NOTES
	  NAME: Invoke-CXServiceAPIPut
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-06
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $Data
	)
    # First check if there is a connection to CX service
    if(!(Test-CXServiceEnvironment)){
		Break
	}
    # Setup Authentication Headers for the API call to retireve the data from CX Service
    $AuthenticationHeaders = Out-CXServiceAuthenticationHeader
	try{
        $Request = Invoke-WebRequest -Uri $URI -Method Put -Headers $AuthenticationHeaders -Body $Data
        if($Request.Content -ne $null){
            ConvertFrom-Json $Request.Content
        }
	} catch {
		throw "An error occured attempting to make a HTTP PUT against $URI"
    }

}

function Invoke-CXServiceAPIPost(){
	<#
    .SYNOPSIS
    Wrapper function which performs a HTTP POST of a JSON payload to the currently connected vCloud Extender (CX Service) API Service.

	.DESCRIPTION
	Wrapper function which performs a HTTP POST of a JSON payload to the currently connected vCloud Extender (CX Service) API Service.

	.PARAMETER URI
    The URI to make the API POST Request against

    .PARAMETER Data
    JSON Payload to POST to the API URI

    .EXAMPLE
    Invoke-CXServiceAPIPost -Uri "https://vcdextender.pigeonnuggets.com/mobility/mgmt/security/certificatechain" -Data ($objCertificateChain | ConvertTo-JSON)

    Performs a HTTP POST request against https://vcdextender.pigeonnuggets.com/mobility/mgmt/security/certificatechain with the JSON payload in the object $objCertificateChain

    .NOTES
	  NAME: Invoke-CXServiceAPIPost
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-06
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $Data
	)
    # First check if there is a connection to CX Service
    if(!(Test-CXServiceEnvironment)){
		Break
	}
    # Setup Authentication Headers for the API call to retireve the data from CX Service
    $AuthenticationHeaders = Out-CXServiceAuthenticationHeader
	try{
        $Request = Invoke-WebRequest -Uri $URI -Method Post -Headers $AuthenticationHeaders -Body $Data -ContentType "application/json"
        if($Request.Content -ne $null){
            ConvertFrom-Json $Request.Content
        }
	} catch {
		throw "An error occured attempting to make a HTTP Post against $URI"
    }
}

function Invoke-CXServiceAPIDelete(){
    <#
    .SYNOPSIS
    Wrapper function which performs a HTTP DELETE with an optional JSON Payload against the currently connected vCloud Extender (CX Service) API.

    .DESCRIPTION
    Wrapper function which performs a HTTP DELETE with an optional JSON Payload against the currently connected vCloud Extender (CX Service) API.

    .PARAMETER URI
    The URI to make the API DELETE Request against

    .PARAMETER Data
    JSON Payload to add to the DELETE request to the API URI

    .EXAMPLE
    Invoke-CXServiceAPIDelete -Uri "https://vcdextender.pigeonnuggets.com/mobility/mgmt/security/trustedcertificates/0000928-a098182-9818271821/"
    Perfoms a HTTP DELETE against the URI https://vcdextender.pigeonnuggets.com/mobility/mgmt/security/trustedcertificates/0000928-a098182-9818271821/

    .NOTES
	  NAME: Invoke-CXServiceAPIDelete
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
    Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$False)] [string] $Data
    )
    # First check if there is a connection to
    if(!(Test-CXServiceEnvironment)){
		Break
	}
    # Setup Authentication Headers for the API call to retireve the data from CX Service
    $AuthenticationHeaders = Out-CXServiceAuthenticationHeader
	try{
		$Request = Invoke-WebRequest -Uri $URI -Method Delete -Headers $AuthenticationHeaders -Body $Data -ContentType "application/json"
        if($Request.Content -ne $null){
            ConvertFrom-Json $Request.Content
        }
    } catch {
		throw "An error occured attempting to make a HTTP Delete against $URI"
	}
}

function Watch-TaskCompleted(){
	<#
	.SYNOPSIS
	 This cmdlet monitors a running task and returns True when the task completes.

	.DESCRIPTION
	 This cmdlet monitors a running task and returns True when the task completes

	.PARAMETER Task
	A PSObject containing a Task object returned by an API POST call

	.PARAMETER Timeout
	Optionally the timeout in seconds before the cmdlet should terminate if the task has not completed.

    Default is 180 seconds.

	.EXAMPLE
	Watch-TaskCompleted -Task $RemoveTask -Timeout 180

	Monitors the task in the object $RemoveTask for a maximum of 60 seconds and returns True when the task completes

	.NOTES
	  NAME: Watch-TaskCompleted
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-06-14
	  STATE: Alpha (Testing)
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [PSObject] $Task,
		[Parameter(Mandatory=$False)]
            [ValidateRange(0,3600)] [int] $Timeout = 180
	)
	$boolTaskComplete = $false
    Do {
        [string] $URI = $global:DefaultCXServer.ServiceURI + "/mgmt/wp/tasks/" + $Task.taskId
        $objTaskStatus = Invoke-CXServiceAPIGet -URI $URI
        # Write debug message
        Write-Debug $objTaskStatus
        Write-Progress -Activity "Task: $($Task.taskName) (Task Id: $($Task.taskId))" -PercentComplete $($objTaskStatus.taskStatus.progress)
		if($objTaskStatus.taskStatus.state -eq "FINISHED"){
            $boolTaskComplete = $true
            if($objTaskStatus.taskStatus.result -ne "SUCCESS"){
                throw "An error occured execuitng task $($Task.taskName) with Task Id $($Task.taskId). Errors: $($objTaskStatus.errorDetails)"
                Break
            }
		}
        $Timeout--
        Start-Sleep -Seconds 1
    } Until (($Timeout -eq 0) -or $boolTaskComplete)
	if(($Timeout -eq 0) -and !$boolTaskComplete){
		throw "A timeout occured waiting for the task $($Task.taskName) with Task Id $($Task.taskId) to complete."
	}
	$boolTaskComplete
}
#endregion

#endregion

#region:CX-Service-Security
function Get-CXServiceCertificateChain(){
    <#
    .SYNOPSIS
	Returns the currently installed Certificate Chain used by the CX Service.

	.DESCRIPTION
	Returns the currently installed Certificate Chain used by the CX Service.

    .EXAMPLE
    Get-CXServiceCertificateChain

    Returns the currently installed Certificate Chain used by the CX Service.

    .NOTES
	  NAME: Get-CXServiceCertificateChain
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    [string] $URI = $global:DefaultCXServer.ServiceURI + "/mgmt/security/certificatechain"
    Invoke-CXServiceAPIGet -URI $URI
}

function Install-CXServiceCertificateChain(){
   <#
    .SYNOPSIS
	Replaces the currently installed certificate used by the CX Service.

	.DESCRIPTION
    This cmdlet replaces the currently installed certificate used by the CX Service.

    VERY Important Notes:
    1) Replacing the certificate requires the Mobility Service to be restarted for changes to take effect.
    2) Changing the certificate after deployment will break the trust established between components. If replacing the CX Cloud Service Certificate all tenant connections will stop working until they update there trusted certificates on-premise. Further all CCM and CCE components will stop functioning until the trusted certificate store is updated. It is recommended that if third-party certificates are to be deployed that they are installed immediately after deployment and before any components are deployed.
    3) The certificate and/or its chain must specify an OCSP responder

    .PARAMETER PEMCertificate
    PEM Encoded X.509 Server Certificate

    .PARAMETER PEMPrivateKey
    PEM Encoded RSA Private Key for the Certificate (without a password)

    .PARAMETER PEMCertificateChain
    A collection of PEM Encoded X.509 Certificates of any Intermediate that is the issuer of the Certificate and the Root CA Certificate. If the Server Certificate is Self-Signed this value is not required. Each Intermediate/CA certificate should be in a seperate file

    .EXAMPLE
    Install-CXServiceCertificateChain -PEMCertificate (Get-Content .\serverCertificate.pem | Out-String) -PEMPrivateKey (Get-Content .\serverCertificate.key | Out-String) -PEMCertificateChain (Get-Content .\RootCAChain.pem | Out-String)

    Installs a new certificate to the connected CX Service stored in the file "serverCertificate.pem". The Private Key for the certificate is stored in a file serverCertificate.key without a password and the CA certificate (with no intermediates) in PEM encoding is installed in RootCAChain.pem

    .EXAMPLE
    Install-CXServiceCertificateChain -PEMCertificate (Get-Content .\serverCertificate.pem | Out-String) -PEMPrivateKey (Get-Content .\serverCertificate.key | Out-String) -PEMCertificateChain ((Get-Content .\RootCAChain.pem | Out-String),(Get-Content .\InternmediateCA.pem | Out-String))

    Installs a new certificate to the connected CX Service stored in the file "serverCertificate.pem". The Private Key for the certificate is stored in a file serverCertificate.key without a password and the CA certificate and an intermediates in PEM encoding is installed in RootCAChain.pem

    .NOTES
	  NAME: Install-CXServiceCertificateChain
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
    Param(
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $PEMCertificate,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $PEMPrivateKey,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [string[]] $PEMCertificateChain
    )
    # Check if connected
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Warn the users that this is dangerous
    Write-Warning "This cmdlet overwrites the currently installed certificate on the connected CX Service. This will cause any tenant connections, CCE and CCM connections to become untrusted and stop functioning. Please proceed with caution/during an organised and planned maintenance window." -WarningAction Inquire
    # Create the JSON Data Payload
    $objCertificateChain = New-Object System.Management.Automation.PSObject
	$objCertificateChain | Add-Member Note* pemCertificate $PEMCertificate
	$objCertificateChain | Add-Member Note* pemPrivateKey $PEMPrivateKey
    $objCertificateChain | Add-Member Note* pemCertificateChain $PEMCertificateChain

    # Perform a HTTP PUT against the API Service
    [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/security/certificatechain"
    Invoke-CXServiceAPIPut -Uri $URI -Data ($objCertificateChain | ConvertTo-JSON)
    Write-Warning "The change will not take effect until the Mobility Service is restarted on the CX Appliance."
}

function Get-CXServiceTrustedCertificates(){
    <#
    .SYNOPSIS
	Returns the details of Certificates currently installed in the Trusted Certificate Store for the CX Service.

	.DESCRIPTION
	Returns the details of Certificates currently installed in the Trusted Certificate Store for the CX Service.

    .EXAMPLE
    Get-CXServiceCertificateChain

    Returns the details of Certificates currently installed in the Trusted Certificate Store for the CX Service.

    .EXAMPLE
    Get-CXServiceTrustedCertificates -CertificateThumbprint "BD:13:D8:8D:8A:92:75:8A:D3:D8:1A:F1:EF:EA:C5:70:17:6D:89:E4"
    Returns the details of the Certificate currently installed in the Trusted Certificate Store for the CX Service with the Thumbprint "BD:13:D8:8D:8A:92:75:8A:D3:D8:1A:F1:EF:EA:C5:70:17:6D:89:E4"

    .NOTES
	  NAME: Get-CXServiceTrustedCertificates
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
	Param(
        [Parameter(Mandatory=$False, ParameterSetName = "ByThumbprint")]
            [ValidateNotNullorEmpty()] [string] $CertificateThumbprint,
        [Parameter(Mandatory=$False, ParameterSetName = "ById")]
            [ValidateNotNullOrEmpty()] [string] $CertificateId,
        [Parameter(Mandatory=$False, ParameterSetName = "ByHost")]
            [ValidateNotNullOrEmpty()] [string] $CertificateHost
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    [string] $URI = $global:DefaultCXServer.ServiceURI + "/mgmt/security/trustedcertificates"
    $TrustedCertificates = Invoke-CXServiceAPIGet -URI $URI
    if($PSCmdlet.ParameterSetName -eq "ById"){
        $TrustedCertificates | ?{$_.certId -eq $CertificateId}
    } elseif($PSCmdlet.ParameterSetName -eq "ByThumbprint"){
        $TrustedCertificates | ?{$_.thumbprint -eq $CertificateThumbprint}
    } elseif($PSCmdlet.ParameterSetName -eq "ByHost"){
        $TrustedCertificates | ?{$CertificateHost -in $_.allowedIPsAndHosts}
    } else {
        $TrustedCertificates
    }
}

function Add-CXServiceTrustedCertificate(){
    <#
    .SYNOPSIS
    Adds an X.509 Server Certificate or CA Chain for a dependent service (CCM, CCE, vCenter, vCloud) into the Trusted Certificate Store for the appliance.

    .DESCRIPTION
    Adds an X.509 Server Certificate or CA Chain for a dependent service (CCM, CCE, vCenter, vCloud) into the Trusted Certificate Store for the appliance.

    .PARAMETER PEMCertificate
    PEM Encoded X.509 Server Certificate

    .PARAMETER AllowedIPsAndHosts
    A collection of host IP addresses that expected to use this certificate

    .PARAMETER Accessibility
    The Accessibility Mode (SOME_HOSTS), (HOST_NAME_OR_IP_MATCHES_CERTICIATE)?

    .EXAMPLE
    Add-CXServiceTrustedCertificate -PEMCertificate (Get-Content "D:\Certificates\vcdextender.pem" | Out-String) -AllowedIPsAndHosts ("192.168.88.181","192.168.88.182")

    Adds a new Server Certificate from file D:\Certificates\vcdextender.pem to the Trusted Certificate Store which can be used by hosts "192.168.88.181" and "192.168.88.182"

    .EXAMPLE
    Add-CXServiceTrustedCertificate -CACertificate -PEMCertificate (Get-Content "D:\Certificates\vcdextender-CAChain.pem" | Out-String)

    Adds a new Server Certificate from the file D:\Certificates\vcdextender-CAChain.pem to the Trusted Certificate Store.

    .NOTES
	  NAME: Add-CXServiceTrustedCertificate
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
    [CmdletBinding(DefaultParameterSetName="ServerCertificate")]
    Param(
        [Parameter(Mandatory=$True,ParameterSetName = "CACertificate")]
            [switch] $CACertificate,
        [Parameter(Mandatory=$True, ParameterSetName = "ServerCertificate")]
        [Parameter(Mandatory=$True, ParameterSetName = "CACertificate")]
            [ValidateNotNullorEmpty()] [string] $PEMCertificate,
        [Parameter(Mandatory=$True, ParameterSetName = "ServerCertificate")]
            [ValidateNotNullorEmpty()] [string[]] $AllowedIPsAndHosts,
        [Parameter(Mandatory=$False, ParameterSetName = "ServerCertificate")]
            [ValidateNotNullorEmpty()] [string] $Accessibility = "SOME_HOSTS"
    )
    # First calculate the SHA256 Certificate thumbprint for the provided PEM Certificate
    [string]$SHA256Thumbprint = Get-SHA2CertificateThumbprint -PEMCertificate $PEMCertificate

    # Check if connected
    if(!(Test-CXServiceEnvironment)){
        Break
    }
    # Check a Certificate already exists with the same thumbprint in the Store
    $MatchedCertificate = Get-CXServiceTrustedCertificates | ?{$_.sha256Thumbprint -eq $SHA256Thumbprint}
    if($MatchedCertificate.Count -ne 0){
        Write-Warning "A certificate with the same thumbprint is already present in the Trusted Certificate Store. This cmdlet overwrites the currently installed certificate on the connected CX Service. This may cause any tenant connections, CCE and CCM connections to become untrusted and stop functioning. Please proceed with caution/during an organised and planned maintenance window." -WarningAction Inquire
        # Need to first remove the existing certificate references
	Remove-CXServiceTrustedCertificate -CertificateId $MatchedCertificate.certId
    }

    if($PSCmdlet.ParameterSetName -eq "CACertificate"){
        # Create the JSON Data Payload
        $objCertificate = New-Object System.Management.Automation.PSObject
        $objCertificate | Add-Member Note* pemCertificate $PEMCertificate
        $objCertificate | Add-Member Note* thumbprint $SHA256Thumbprint
        $objCertificate | Add-Member Note* ca $True
    } elseif($PSCmdlet.ParameterSetName -eq "ServerCertificate"){
        # Create the JSON Data Payload
        $objCertificate = New-Object System.Management.Automation.PSObject
        $objCertificate | Add-Member Note* pemCertificate $PEMCertificate
        $objCertificate | Add-Member Note* allowedIPsAndHosts $AllowedIPsAndHosts
        $objCertificate | Add-Member Note* accessibility $Accessibility
        $objCertificate | Add-Member Note* thumbprint $SHA256Thumbprint
    }

    # Perform a HTTP POST against the API Service
    [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/security/trustedcertificates"
    Invoke-CXServiceAPIPOST -Uri $URI -Data ($objCertificate | ConvertTo-JSON)
}

function Remove-CXServiceTrustedCertificate(){
    <#
    .SYNOPSIS
    Removes an X.509 Server Certificate or CA Chain for a dependent service (CCM, CCE, vCenter, vCloud) from the Trusted Certificate Store for the appliance.

    .DESCRIPTION
    Removes an X.509 Server Certificate or CA Chain for a dependent service (CCM, CCE, vCenter, vCloud) from the Trusted Certificate Store for the appliance.

    .PARAMETER CertificateThumbprint
    The SHA256 Thumbprint of the X.509 Server Certificate to remove

    .PARAMETER CertificateId
    The Certificate Id of the X.509 Server Certificate to remove

    .EXAMPLE
    Remove-CXServiceTrustedCertificate -CertificateId "55736fa0-0a80-4e8c-acfc-9cd6976cd372"

    Removes the certificate from the trusted store with the Certificate Id of 55736fa0-0a80-4e8c-acfc-9cd6976cd372

    .EXAMPLE
    Remove-CXServiceTrustedCertificate -CertificateThumbprint "58b476a3b8a72ed977713892c0cb54b542c1f670"

    Removes the certificate from the trusted store with the Certificate Thumbprint of 58b476a3b8a72ed977713892c0cb54b542c1f670

    .NOTES
	  NAME: Remove-CXServiceTrustedCertificate
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
 	Param(
        [Parameter(Mandatory=$False, ParameterSetName = "ByThumbprint")]
            [ValidateNotNullorEmpty()] [string] $CertificateThumbprint,
        [Parameter(Mandatory=$False, ParameterSetName = "ById")]
            [ValidateNotNullorEmpty()] [string] $CertificateId
    )
    # Check if connected
    if(!(Test-CXServiceEnvironment)){
        Break
    }

    # Next confirm that the certificate provided exists
    if($PSCmdlet.ParameterSetName -eq "ById"){
        $MatchedCertificate = Get-CXServiceTrustedCertificates -CertificateId $CertificateId
    }
    elseif($PSCmdlet.ParameterSetName -eq "ByThumbprint"){
        $MatchedCertificate = Get-CXServiceTrustedCertificates -CertificateThumbprint $CertificateThumbprint
    }
    if($MatchedCertificate.Count -eq 0){
        throw "A certificate matching the input critera does not currently exist in the Trusted Certificate Store. Please verify the ID or Thumbprint provided and try this action again."
    } else{
        # Contstruct the API call to remove the certificate
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/security/trustedcertificates/" + $MatchedCertificate.certId
        Invoke-CXServiceAPIDelete -Uri $URI
    }
}
#endregion

#region:Management-vCenter
function Get-CXServicevCenter(){
    <#
    .SYNOPSIS
    Retrieves the configuration of the currently configured Management vCenter for the vCloud Extender Cloud Service or Connector Service

    .DESCRIPTION
    Retrieves the configuration of the currently configured Management vCenter for the vCloud Extender deployment. This is the vCenter where all CX Appliances are deployed.
    This cmdlet can be executed against a CX Cloud Service or a Cloud Connector Service

    .EXAMPLE
    Get-CXServicevCenter

    Returns the configured vCenter properties (if any exist)

    .NOTES
	  NAME: Get-CXServicevCenter
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-13
    #>
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    [string] $URI = $global:DefaultCXServer.ServiceURI + "/mgmt/vc"
    $vCenter = Invoke-CXServiceAPIGet -URI $URI
    $vCenter
}

function Add-CXServicevCenter(){
    <#
    .SYNOPSIS
    Configures the Management vCenter for the the currently connected vCloud Extender Cloud Service or Connector Service

    .DESCRIPTION
    Configures the Management vCenter for the the currently connected vCloud Extender Cloud Service or Connector Service

    .PARAMETER Name
    The display name of the vCenter Server

    .PARAMETER Address
    The FQDN or IP address of the vCenter Server

    .PARAMETER Username
    The Username (with Administrative Rights) to use for the vCenter Server

    .PARAMETER Password
    The Password for the User

    .PARAMETER LookupServiceURL
    The URI to the Lookup Service (eg. https://vcenter.fqdn/lookupservice/sdk")

    .EXAMPLE
    Add-CXServicevCenter -Name "LABVCSA1" -Address "labvc1.pigeonnuggets.com" -Username "administrator@vsphere.pigeonnuggets.com" -Password "Password" -LookupServiceURL "https://labvc1.pigeonnuggets.com/lookupservice/sdk"

    Adds a new Management vCenter "LABVCAS1" with the FQDN "labvc1.pigeonnuggets.com" as the Management vCenter using the credentials and the Lookup Service URL specified

    .NOTES
	  NAME: Add-CXServicevCenter
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Name,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Address,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Username,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Password,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $LookupServiceURL
        )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Check if this is configured already
    if((Get-CXServicevCenter) -ne $null){
        throw "A Management vCenter is already configured, multiple management VCs can't be added. Please configure it using the Set-CXServicevCenter cmdlet."
    } else {
        # Create the JSON Data Payload
        $objManagementvCenter = New-Object System.Management.Automation.PSObject
        $objManagementvCenter | Add-Member Note* type "vcenter"
        $objManagementvCenter | Add-Member Note* name $Name
        $objManagementvCenter | Add-Member Note* url ("https://" + $Address + ":443")
        # Create the credentials object
        $objVCCred = New-Object System.Management.Automation.PSObject
        $objVCCred | Add-Member Note* username $Username
        $objVCCred | Add-Member Note* password $Password
        $objManagementvCenter | Add-Member Note* adminUser $objVCCred
        $objManagementvCenter | Add-Member Note* infraManagerType "VCENTER_SERVER"
        $objManagementvCenter | Add-Member Note* lookupServiceUrl $LookupServiceURL
        $objManagementvCenter | Add-Member Note* ip $Address

        # Perform a HTTP POST against the API Service
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/vc"
        Invoke-CXServiceAPIPOST -Uri $URI -Data ($objManagementvCenter | ConvertTo-JSON)
    }
}

function Set-CXServicevCenter(){
    <#
    .SYNOPSIS
    Updates the properties of the Management vCenter for the the currently connected vCloud Extender Cloud Service or Connector Service

    .DESCRIPTION
    Updates the properties of the Management vCenter for the the currently connected vCloud Extender Cloud Service or Connector Service

    .PARAMETER Name
    The Name of the vCenter Server

    .PARAMETER Address
    The FQDN or IP address of the vCenter Server

    .PARAMETER Username
    The Username (with Administrative Rights) to use for the vCenter Server

    .PARAMETER Password
    The password for the specified SSO user

    .PARAMETER LookupServiceURL
    The URI to the Lookup Service (eg. https://vcenter.fqdn/lookupservice/sdk")

    .EXAMPLE
    Set-CXServicevCenter -Name "VC2" -Password "Password!123"

    Updates the vCenter Display Name to VC2 for the Management vCenter

    .EXAMPLE
    Set-CXServicevCenter -Name "VC2" -Address "labvc2.pigeonnuggets.com" -Password "Password!123"

    Updates the vCenter Display Name to VC2 and the address to labvc2.pigeonnuggets.com for the Management vCenter

    .NOTES
	  NAME: Set-CXServicevCenter
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [string] $Name,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [string] $Address,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [string] $Username,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Password,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [string] $LookupServiceURL
    )
    # First check that a Management vCenter is configured
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    $ManagementvCenter = Get-CXServicevCenter
    if(($ManagementvCenter) -eq $null){
        throw "The Management vCenter is currently not configured. Please configure it using the Add-CXServicevCenter cmdlet."
    } else {
        # Check which parameters were provided and update the object with the new values
        if(!([string]::IsNullOrEmpty($Name))){
            $ManagementvCenter.name = $Name
        }
        if(!([string]::IsNullOrEmpty($Address))){
            $ManagementvCenter.url = $Address
        }
        if(!([string]::IsNullOrEmpty($Username))){
            $ManagementvCenter.adminUser.username = $Username
        }
        if(!([string]::IsNullOrEmpty($LookupServiceURL))){
            $ManagementvCenter.lookupServiceUrl = $LookupServiceURL
        }
        $ManagementvCenter.adminUser.password = $Password
    }
    # Perform a HTTP PUT against the API Service
    [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/vc"
    Invoke-CXServiceAPIPut -Uri $URI -Data ($ManagementvCenter | ConvertTo-JSON)
}
#endregion

#region:CCE
function Get-CXServiceCCE(){
    <#
    .SYNOPSIS
    Returns a list of Registered CCE (Cloud Continuity Engines) registered against the CX Service

    .DESCRIPTION
    Returns a list of Registered CCE (Cloud Continuity Engines) registered against the CX Service

    .PARAMETER EntityId
    The EntityId

    .PARAMETER Name
    The Name of the CCE

    .EXAMPLE
    Get-CXServiceCCE

    Returns all CCE objects registered against the CX Service

    .EXAMPLE
    Get-CXServiceCCE -EntityId "8aed4131-5da4-48b0-a7d8-b5492a196455"

    Returns the CCE object with the Id "8aed4131-5da4-48b0-a7d8-b5492a196455"

    .EXAMPLE
    Get-CXServiceCCE -Name "LABCXREPAPL1"
    Returns the CCE object with the Name "8aed4131-5da4-48b0-a7d8-b5492a196455"

    .NOTES
	  NAME: Get-CXServiceCCE
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
	Param(
        [Parameter(Mandatory=$False, ParameterSetName = "ById")]
            [ValidateNotNullOrEmpty()] [string] $EntityId,
        [Parameter(Mandatory=$False, ParameterSetName = "ByName")]
            [ValidateNotNullOrEmpty()] [string] $Name
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    [string] $URI = $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/"
    $CCEReplicators = Invoke-CXServiceAPIGet -URI $URI
    if($PSCmdlet.ParameterSetName -eq "ById"){
        $CCEReplicators | ?{$_.entityId -eq $EntityId}
    } elseif($PSCmdlet.ParameterSetName -eq "ByName"){
        $CCEReplicators | ?{$_.entityName -eq $Name}
    } else {
        $CCEReplicators
    }
}

function Remove-CXServiceCCE(){
    <#
    .SYNOPSIS
    Removes a Registered CCE (Cloud Continuity Engines) registered against the CX Service

    .DESCRIPTION
    Removes a Registered CCE (Cloud Continuity Engines) registered against the CX Service

    .PARAMETER Name
    The Name of the CCE to remove from the System

    .PARAMETER EntityId
    The EntityId of the CCE to remove from the System

    .EXAMPLE
    Remove-CXServiceCCE -Name "LABCXREPAPL1"

    Removes the CCE appliance with the name LABCXREPAPL1

    .EXAMPLE
    Remove-CXServiceCCE -EntityId "LABCXREPAPL1"

    Removes the CCE appliance with the Entity Id of 8aed4131-5da4-48b0-a7d8-b5492a196455 from the system

    .NOTES
	  NAME: Remove-CXServiceCCE
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
 	Param(
        [Parameter(Mandatory=$True, ParameterSetName = "ByName")]
            [ValidateNotNullorEmpty()] [string] $Name,
        [Parameter(Mandatory=$True, ParameterSetName = "ById")]
            [ValidateNotNullorEmpty()] [string] $EntityId
    )
    # Check if connected
    if(!(Test-CXServiceEnvironment)){
        Break
    }
    # Next confirm that the CCE provided exists
    if($PSCmdlet.ParameterSetName -eq "ById"){
        $CCE = Get-CXServiceCCE -EntityId $EntityId
    }
    elseif($PSCmdlet.ParameterSetName -eq "ByName"){
        $CCE = Get-CXServiceCCE -Name $Name
    }
    if($CCE -eq $null){
        throw "A CCE Replicator matching the input critera could not be found. Please verify the ID or Name provided and try this action again."
    } else{
        # Contstruct the API call to remove the CCE Appliance /mgmt/wp/replicators/Id/uninstall
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/" + $CCE.EntityId + "/uninstall"
        $objRemovalTask = Invoke-CXServiceAPIDelete -Uri $URI
        $objTaskComplete = Watch-TaskCompleted -Task $objRemovalTask -Timeout 300
    }
}

function Add-CXServiceCCE(){
    <#
    .SYNOPSIS
    Deploys a new Cloud Continuity Engine (CCE) to the Management vCenter of the currently connected vCloud Extender installation.

    .DESCRIPTION
    Deploys a new Cloud Continuity Engine (CCE) to the Management vCenter of the currently connected vCloud Extender installation.

    .PARAMETER Name
    The VM Name of the CCE

    .PARAMETER DatacenterName
    The vCenter Datacenter Name where the CCE will be deployed. Value is case-sensative

    .PARAMETER ClusterName
    The vCenter Cluster Name where the CCE will be deployed. Value is case-sensative

    .PARAMETER DataStoreName
    The vCenter Datastore Name where the CCE will be deployed. Value is case-sensative

    .PARAMETER EnableSSH
    If enabled SSH will be enabled on the CCE
    Default: $False

    .PARAMETER NetworkName
    The vCenter Port Group Name where the CCE will be connected. Value is case-sensative.

    .PARAMETER IPAddress
    The IPv4 static IP address for the CCE

    .PARAMETER Gateway
    The IPv4 Gateway for the network interface

    .PARAMETER Netmask
    The IPv4 Network Mask for the network interface

    .PARAMETER RootPassword
    The Root Password for the CCE appliance

    .PARAMETER DNS
    A collection of DNS Server IPv4 addresses for the interface.

    .EXAMPLE
    Add-CXServiceCCE -Name "LABREPAPL1" -DatacenterName "DC1" -ClusterName "NUCs" -DataStoreName "vsanDatastore" -EnableSSH $true -NetworkName "Lab" -IPAddress "192.168.88.182" -Gateway "192.168.88.1" -NetMask "255.255.255.0" -RootPassword "password" -DNS ("192.168.88.10","192.168.88.11")

    Deploys a new CCE Appliance with the name LABREPAPL1 to vCenter Datacenter DC1 (HA Cluster NUCs) on the vsanDatastore. SSH will be enabled and the machine will be connected to the Lab network with static IP of 192.168.88.182 and a Root Password of password.

    .NOTES
	  NAME: Add-CXServiceCCE
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Name,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $DatacenterName,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $ClusterName,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $DataStoreName,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [bool] $EnableSSH=$false,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $NetworkName,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string] $IPAddress,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string] $Gateway,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string] $Netmask,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $RootPassword,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string[]] $DNS
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # TO DO: Check if an appliance already exists with the same properties (ie. Virtual Machine name etc.)
    # Check if the Management vCenter has been configured
    $ManagementvCenter = Get-CXServicevCenter
    if($ManagementvCenter -eq $null){
        throw "The Management vCenter has not yet been configured for the connected CX Cloud Service. Please configure a Management vCenter and try again."
    }
    # Construct the JSON Payload for the new CCE
    $objCCEService = New-Object System.Management.Automation.PSObject
    $objCCEService | Add-Member Note* name $Name
    $objCCEService | Add-Member Note* dataCenterName $DatacenterName
    $objCCEService | Add-Member Note* dataStoreName $DataStoreName
    $objCCEService | Add-Member Note* enableSSH $EnableSSH
    $objCCEService | Add-Member Note* clusterName $ClusterName
    $objCCEService | Add-Member Note* infraManagerId $ManagementvCenter.id
    # Create the NIC configuration object
    $objCCEServiceNIC = New-Object System.Management.Automation.PSObject
    $objCCEServiceNIC | Add-Member Note* dns $DNS
    $objCCEServiceNIC | Add-Member Note* networkName $NetworkName
    $objCCEServiceNIC | Add-Member Note* ipAddress $IPAddress
    $objCCEServiceNIC | Add-Member Note* gateway $Gateway
    $objCCEServiceNIC | Add-Member Note* netMask $Netmask
    $objCCEServiceNIC | Add-Member Note* mode "STATIC"
    $objCCEService | Add-Member Note* nic $objCCEServiceNIC
    $objCCEService | Add-Member Note* guestPassword $RootPassword

    # Perform a HTTP POST against the API Service
    [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/install?trust=true"
    $createCCETask = Invoke-CXServiceAPIPOST -Uri $URI -Data ($objCCEService | ConvertTo-JSON -Depth 4)
    $objTaskComplete = Watch-TaskCompleted -Task $createCCETask -Timeout 300
}

function Set-CXServiceCCE(){
    <#
    .SYNOPSIS
    Sets the proxy (external) endpoint address and port for the Cloud Continuity Engine (CCE).

    .DESCRIPTION
    Sets the proxy (external) endpoint address and port for the Cloud Continuity Engine (CCE).

    .PARAMETER Name
    The Name of the CCE

    .PARAMETER PublicIPAddress
    The IPv4 Public IP Address that the CCE is accessible via.

    .PARAMETER PublicHostName
    The Publicly Resovlable Address of the CCE. This is used for constructing the external API URI

    .PARAMETER Port
    The TCP Port for the CCE LWD Proxy Service.
    Default: 44045

    .EXAMPLE
    Set-CXServiceCCE -Name "LABREPAP1" -PublicIPAddress "198.51.100.89"

    Sets the Public IP address for the CCE with the name LABREPAP1 to 198.51.100.89 on Port 44045

    .NOTES
	  NAME: Set-CXServiceCCE
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
	Param(
        [Parameter(Mandatory=$True, ParameterSetName = "SetPublicEndpoint")]
            [ValidateNotNullOrEmpty()] [string] $Name,
        [Parameter(Mandatory=$True, ParameterSetName = "SetPublicEndpoint")]
            [ValidateNotNullOrEmpty()] [string] $PublicIPAddress,
        [Parameter(Mandatory=$false, ParameterSetName = "SetPublicEndpoint")]
            [ValidateNotNullOrEmpty()] [string] $PublicHostName,
        [Parameter(Mandatory=$False, ParameterSetName = "SetPublicEndpoint")]
            [int] $Port=44045
    )
    # First test if we are connected
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Next attempt to retrieve the CCM
    $CCEService = Get-CXServiceCCE -Name $Name
    if($CCMService.Count -eq 0){
        throw "Unable to find a CCE registered against this CX Cloud Service with the Name $Name. Please verify and try again."
    }
    # Check what is being updated
    if($PSCmdlet.ParameterSetName -eq "SetPublicEndpoint"){
        if($PublicHostName -ne $null){
            $PublicURL = $PublicHostName + ":" + $Port
        } else {
            $PublicURL = $PublicIPAddress + ":" + $Port
        }
        # Create the JSON Data Payload
        $objPublicIPConfiguration = New-Object System.Management.Automation.PSObject
        $objPublicIPConfiguration | Add-Member Note* url $PublicURL
        $objPublicIPConfiguration | Add-Member Note* lwdIpAddress $PublicIPAddress
        $objPublicIPConfiguration | Add-Member Note* lwdPort $Port

         # Perform a HTTP POST against the API Service
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/" + $CCEService.entityId + "/publicendpoint"
        Invoke-CXServiceAPIPost -Uri $URI -Data ($objPublicIPConfiguration | ConvertTo-JSON)
    }
}

function Enable-CXServiceCCE(){
    <#
    .SYNOPSIS
    Activates the Cloud Continunity Engine (CCE)

    .DESCRIPTION
    Sets up the connection to the Resource vCenter for the CCE and registers it as managed by the CCM.

    .PARAMETER Name
    The Name of the CCE Appliance

    .PARAMETER AppliancePassword
    The new Root Password to set for the CCE Appliance

    .PARAMETER LookupServiceURI
    The URI to the Lookup Service for the Resource vCenter (eg. https://vcenter.fqdn/lookupservice/sdk")

    .PARAMETER ResourcevCenterSSOUser
    The SSO Username (with Administrative Rights) to use for the Resource vCenter Server

    .PARAMETER ResourcevCenterSSOPassword
    The Password for the SSO Username defined in ResourcevCenterSSOUser

    .PARAMETER PublicEndpointURI
    The Publicly Resovlable Address of the CCE. This is used for constructing the external API URI

    .EXAMPLE
    Enable-CXServiceCCE -Name "LABREPAPL1" -AppliancePassword "Password!123" -LookupServiceURI "https://labvc1.pigeonnuggets.com/lookupservice/sdk" -ResourcevCenterSSOUser "administrator@vsphere.pigeonnuggets.com" -ResourcevCenterSSOPassword "Password!123" -PublicEndpointURI "198.51.100.89:44045"

    Activates the CCE LABREPAPL1 against the Resource vCenter and sets the Public Endpoint as "198.51.100.89:8043"
    .NOTES
	  NAME: Enable-CXServiceCCE
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)] [string] $Name,
        [Parameter(Mandatory=$True)] [string] $AppliancePassword,
        [Parameter(Mandatory=$False)] [string] $LookupServiceURI,
        [Parameter(Mandatory=$False)] [string] $ResourcevCenterSSOUser,
        [Parameter(Mandatory=$False)] [string] $ResourcevCenterSSOPassword,
        [Parameter(Mandatory=$False)] [string] $PublicEndpointURI
    )
    # First test if we are connected
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Next attempt to retrieve the CCM
    $CCEService = Get-CXServiceCCE -Name $Name
    if($CCEService -eq $null){
        throw "Unable to find a CCE registered against this CX Cloud Service with the Name $Name. Please verify and try again."
    } else {
        # Only configure if it has not already been configured
        if($CCEService.configured -eq $false){
            # Create the JSON Data Payload
            $objCCEService = New-Object System.Management.Automation.PSObject
            $objCCEService | Add-Member Note* oldRootPassword "password"
            $objCCEService | Add-Member Note* newRootPassword $AppliancePassword
            $objCCEService | Add-Member Note* lsUrl $LookupServiceURI
            $objCCEService | Add-Member Note* ssoUser $ResourcevCenterSSOUser
            $objCCEService | Add-Member Note* ssoPassword $ResourcevCenterSSOPassword
            $objCCEService | Add-Member Note* description "replicator"
            $objCCEService | Add-Member Note* owner "*"
            $objCCEService | Add-Member Note* site "cloud"
            $objCCEService | Add-Member Note* id $CCEService.entityId
            $objCCEService | Add-Member Note* isActivated $False
            $objCCEService | Add-Member Note* configured $False
            $objCCEService | Add-Member Note* confirmPassword $AppliancePassword

            # Perform a HTTP POST against the API Service
            [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/" + $CCEService.entityId + "/configure?trust=true"
            $taskConfigurReplictor = Invoke-CXServiceAPIPOST -Uri $URI -Data ($objCCEService | ConvertTo-JSON)
        } else {
            Write-Warning "The CCE is already marked as configured, no changes will be made to Resource vCenter configuration."
        }
        # Next set the Public IP Endpoint
        $URIAddressPart = $PublicEndpointURI.Split(":")[0]
        $URIPort = $PublicEndpointURI.Split(":")[1]

        $PublicEndpoint = New-Object System.Management.Automation.PSObject
        $PublicEndpoint | Add-Member Note* url $LookupServiceURI
        $PublicEndpoint | Add-Member Note* lwdIpAddress $URIAddressPart
        $PublicEndpoint | Add-Member Note* lwdPort $URIPort

        [string] $SetPublicEndpointURI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/" + $CCEService.entityId + "/publicendpoint"
        $taskPublicURIConfig = Invoke-CXServiceAPIPOST -Uri $SetPublicEndpointURI -Data ($PublicEndpoint | ConvertTo-JSON)

        # Finally Register with the CCM
        $CCMRegistration = New-Object System.Management.Automation.PSObject
        $CCMRegistration | Add-Member Note* lsUrl $LookupServiceURI
        $CCMRegistration | Add-Member Note* ssoUser $ResourcevCenterSSOUser
        $CCMRegistration | Add-Member Note* ssoPassword $ResourcevCenterSSOUser
        $CCMRegistration | Add-Member Note* id $CCEService.entityId
        $CCMRegistration | Add-Member Note* isActivated $false
        $CCMRegistration | Add-Member Note* configured $true

        [string] $CCERegistrationURI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/replicators/" + $CCEService.entityId + "/register"
        Invoke-CXServiceAPIPOST -Uri $CCERegistrationURI -Data ($PublicEndpoint | ConvertTo-JSON)
    }
}

#endregion

#region:CCM
function Get-CXServiceCCM(){
    <#
    .SYNOPSIS
    Returns a list of Registered CCM (Cloud Continuity Managers) registered against the CX Service

    .DESCRIPTION
    Returns a list of Registered CCM (Cloud Continuity Managers) registered against the CX Service

    .PARAMETER EntityId
    The EntityId

    .PARAMETER Name
    The Name of the CCM

    .EXAMPLE
    Get-CXServiceCCM

    Returns all CCM objects registered against the CX Service

    .EXAMPLE
    Get-CXServiceCCM -EntityId "8aed4131-5da4-48b0-a7d8-b5492a196455"

    Returns the CCM object with the Id "8aed4131-5da4-48b0-a7d8-b5492a196455"

    .EXAMPLE
    Get-CXServiceCCM -Name "LABCXREP1"
    Returns the CCM object with the Name "8aed4131-5da4-48b0-a7d8-b5492a196455"

    .NOTES
	  NAME: Get-CXServiceCCM
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
	Param(
        [Parameter(Mandatory=$False, ParameterSetName = "ById")]
            [ValidateNotNullOrEmpty()] [string] $EntityId,
        [Parameter(Mandatory=$False, ParameterSetName = "ByName")]
            [ValidateNotNullOrEmpty()] [string] $Name
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    [string] $URI = $global:DefaultCXServer.ServiceURI + "/mgmt/wp/managers/"
    $CCMManagers = Invoke-CXServiceAPIGet -URI $URI
    if($PSCmdlet.ParameterSetName -eq "ById"){
        $CCMManagers | ?{$_.entityId -eq $EntityId}
    } elseif($PSCmdlet.ParameterSetName -eq "ByName"){
        $CCMManagers | ?{$_.entityName -eq $Name}
    } else {
        $CCMManagers
    }
}

function Add-CXServiceCCM(){
    <#
    .SYNOPSIS
    Deploys a new Cloud Continuity Manager (CCM) to the Management vCenter of the currently connected vCloud Extender installation.

    .DESCRIPTION
    Deploys a new Cloud Continuity Manager (CCM) to the Management vCenter of the currently connected vCloud Extender installation.

    .PARAMETER Name
    The VM Name of the CCM

    .PARAMETER DatacenterName
    The vCenter Datacenter Name where the CCM will be deployed. Value is case-sensative

    .PARAMETER ClusterName
    The vCenter Cluster Name where the CCM will be deployed. Value is case-sensative

    .PARAMETER DataStoreName
    The vCenter Datastore Name where the CCM will be deployed. Value is case-sensative

    .PARAMETER EnableSSH
    If enabled SSH will be enabled on the CCM
    Default: $False

    .PARAMETER NetworkName
    The vCenter Port Group Name where the CCM will be connected. Value is case-sensative.

    .PARAMETER IPAddress
    The IPv4 static IP address for the CCM

    .PARAMETER Gateway
    The IPv4 Gateway for the network interface

    .PARAMETER Netmask
    The IPv4 Network Mask for the network interface

    .PARAMETER RootPassword
    The Root Password for the CCM appliance

    .PARAMETER DNS
    A collection of DNS Server IPv4 addresses for the interface.

    .EXAMPLE
    Add-CXServiceCCM -Name "LABREP1" -DatacenterName "DC1" -ClusterName "NUCs" -DataStoreName "vsanDatastore" -EnableSSH $true -NetworkName "Lab" -IPAddress "192.168.88.181" -Gateway "192.168.88.1" -NetMask "255.255.255.0" -RootPassword "password" -DNS ("192.168.88.10","192.168.88.11")

    Deploys a new CCM Appliance with the name LABREP1 to vCenter Datacenter DC1 (HA Cluster NUCs) on the vsanDatastore. SSH will be enabled and the machine will be connected to the Lab network with static IP of 192.168.88.181 and a Root Password of password.

    .NOTES
	  NAME: Add-CXServiceCCM
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $Name,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $DatacenterName,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $ClusterName,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $DataStoreName,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [bool] $EnableSSH=$false,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $NetworkName,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string] $IPAddress,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string] $Gateway,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string] $Netmask,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullorEmpty()] [string] $RootPassword,
        [Parameter(Mandatory=$True)]
            [ValidateScript({Test-ValidIPString -IPAddress $_ })] [string[]] $DNS
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Check if a CCM already exists (there can be only one per deployment)
    if((Get-CXServiceCCM) -ne $null){
        throw "A Cloud Continunity Manager (CCM) has already been configured. Only one CCM can be configured for each CX Cloud Service."
    }
    # Check if the Management vCenter has been configured
    $ManagementvCenter = Get-CXServicevCenter
    if($ManagementvCenter -eq $null){
        throw "The Management vCenter has not yet been configured for the connected CX Cloud Service. Please configure a Management vCenter and try again."
    }
    # Construct the JSON Payload for the new CCM
    $objCCMService = New-Object System.Management.Automation.PSObject
    $objCCMService | Add-Member Note* name $Name
    $objCCMService | Add-Member Note* dataCenterName $DatacenterName
    $objCCMService | Add-Member Note* dataStoreName $DataStoreName
    $objCCMService | Add-Member Note* enableSSH $EnableSSH
    $objCCMService | Add-Member Note* clusterName $ClusterName
    $objCCMService | Add-Member Note* infraManagerId $ManagementvCenter.id
    # Create the NIC configuration object
    $objCCMServiceNIC = New-Object System.Management.Automation.PSObject
    $objCCMServiceNIC | Add-Member Note* dns $DNS
    $objCCMServiceNIC | Add-Member Note* networkName $NetworkName
    $objCCMServiceNIC | Add-Member Note* ipAddress $IPAddress
    $objCCMServiceNIC | Add-Member Note* gateway $Gateway
    $objCCMServiceNIC | Add-Member Note* netMask $Netmask
    $objCCMServiceNIC | Add-Member Note* mode "STATIC"
    $objCCMService | Add-Member Note* nic $objCCMServiceNIC
    $objCCMService | Add-Member Note* guestPassword $RootPassword

    # Perform a HTTP POST against the API Service
    [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/managers/install?trust=true"
    $createCCMTask = Invoke-CXServiceAPIPOST -Uri $URI -Data ($objCCMService | ConvertTo-JSON -Depth 4)
    $objTaskComplete = Watch-TaskCompleted -Task $createCCMTask -Timeout 300
}

function Remove-CXServiceCCM(){
    <#
    .SYNOPSIS
    Removes a Registered CCM (Cloud Continuity Manager) registered against the CX Service

    .DESCRIPTION
    Removes a Registered CCM (Cloud Continuity Manager) registered against the CX Service

    .PARAMETER Name
    The Name of the CCM to remove from the System

    .PARAMETER EntityId
    The EntityId of the CCM to remove from the System

    .EXAMPLE
    Remove-CXServiceCCM -Name "LABCXREP1"

    Removes the CCM appliance with the name LABCXREP1

    .EXAMPLE
    Remove-CXServiceCCM -EntityId "LABCXREP1"

    Removes the CCM appliance with the Entity Id of 8aed4131-5da4-48b0-a7d8-b5492a196455 from the system

    .NOTES
	  NAME: Remove-CXServiceCCM
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
 	Param(
        [Parameter(Mandatory=$True, ParameterSetName = "ByName")]
            [ValidateNotNullorEmpty()] [string] $Name,
        [Parameter(Mandatory=$True, ParameterSetName = "ById")]
            [ValidateNotNullorEmpty()] [string] $EntityId
    )
    # Check if connected
    if(!(Test-CXServiceEnvironment)){
        Break
    }
    # Next confirm that the CCM that we are targeting exists
    if($PSCmdlet.ParameterSetName -eq "ById"){
        $CCM = Get-CXServiceCCM -EntityId $EntityId
    }
    elseif($PSCmdlet.ParameterSetName -eq "ByName"){
        $CCM = Get-CXServiceCCM -Name $Name
    }
    if($CCM -eq $null){
        throw "A CCM Manager matching the input critera could not be found. Please verify the ID or Name provided and try this action again."
    } else{
        # Contstruct the API call to remove the CCM DELETE
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/managers/" + $CCM.EntityId + "/uninstall"
        $objRemovalTask = Invoke-CXServiceAPIDelete -Uri $URI
        $objTaskComplete = Watch-TaskCompleted -Task $objRemovalTask -Timeout 300
    }
}

function Enable-CXServiceCCM(){
    <#
    .SYNOPSIS
    Activates the Cloud Continunity Manager (CCM)

    .DESCRIPTION
    Sets the password for the appliance, sets the Public IP address that the appliance will be contacted from extermally (NAT Address) and sets the Manager ready for new CCE connections.

    .PARAMETER Name
    The Name of the CCM to Activate

    .PARAMETER Password
    The new root password for the appliance

    .PARAMETER PublicIP
    The Publicly Routable IP address that will be used for the CCM

    .PARAMETER PublicPort
    The TCP Port externally that the CCM will accept connections from (Default is 8044)

    .EXAMPLE
    Enable-CXServiceCCM -Name "LABREP1" -Password "Pa$$w0rd!" -PublicIP "198.51.100.89" -PublicPort 8044

    Activates the CCM LABREP1 setting the root password to Pa$$w0rd! and also sets the Public address that the CCM will accept connections from to 198.51.100.89:8044

    .NOTES
	  NAME: Enable-CXServiceCCM
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)] [string] $Name,
        [Parameter(Mandatory=$True)] [string] $Password,
        [Parameter(Mandatory=$True)] [string] $PublicIP,
        [Parameter(Mandatory=$True)] [int] $PublicPort=8044
    )
    # First test if we are connected
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Next attempt to retrieve the CCM
    $CCMService = Get-CXServiceCCM -Name $Name
    if($CCMService.Count -eq 0){
        throw "Unable to find a CCM registered against this CX Cloud Service with the Name $Name. Please verify and try again."
    } else {
        # Create the JSON Data Payload
        $objCCMService = New-Object System.Management.Automation.PSObject
        $objCCMService | Add-Member Note* oldRootPassword "password"
        $objCCMService | Add-Member Note* newRootPassword $Password
        $objCCMService | Add-Member Note* confirmPassword $Password
        # Perform a HTTP POST against the API Service
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/managers/" + $CCMService.entityId + "/configure?trust=true"
        Invoke-CXServiceAPIPOST -Uri $URI -Data ($objCCMService | ConvertTo-JSON)

        # Next set Public IP address if it was provided
        # Create the JSON Data Payload
        $objPublicIPConfiguration = New-Object System.Management.Automation.PSObject
        $objPublicIPConfiguration | Add-Member Note* url $CCMService.apiURL
        $objPublicIPConfiguration | Add-Member Note* ipAddress $PublicIP
        $objPublicIPConfiguration | Add-Member Note* port $PublicPort

         # Perform a HTTP POST against the API Service
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mgmt/wp/managers/" + $CCMService.entityId + "/publicendpoint"
        Invoke-CXServiceAPIPost -Uri $URI -Data ($objPublicIPConfiguration | ConvertTo-JSON)
    }
}
#endregion


#region:Cloud-Resoruces
function Get-CXServiceVCDConfiguration(){
    <#
    .SYNOPSIS
    Returns the currently registered vCloud Director registered against the CX Service

    .DESCRIPTION
    Returns the currently registered vCloud Director registered against the CX Service and the assosiated Resoruce vCenter objects

    .EXAMPLE
    Get-CXServiceVCDConfiguration

    Returns the vCloud Director objects registered against the CX Service

    .NOTES
	  NAME: Get-CXServiceVCDConfiguration
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    [string] $URI = $global:DefaultCXServer.ServiceURI + "/mm/sites"
    $vCloudInstances = Invoke-CXServiceAPIGet -URI $URI
    # Check if anything was returned
    if($vCloudInstances -ne $null){
        # Next we need to query for the Resoruce vCenters that are associated with the Site
        $colResourcevCenter = Get-CXServiceVCDResourcevCenter -InfraConnectorId $vCloudInstances.infraConnectorId
        $vCloudInstances | Add-Member Note* ResourcevCenters $colResourcevCenter
    }
    # Create an object to return to the caller
    $vCloudInstances
}

function Get-CXServiceVCDResourcevCenter(){
    <#
    .SYNOPSIS
    Returns the Resource vCenter details for Resource vCenters registered against a provided vCloud Director Site

    .DESCRIPTION
    Returns the Resource vCenter details for Resource vCenters registered against a provided vCloud Director Site

    .PARAMETER InfraConnectorId
    The InfraConnectorId of the Resource vCenter Site

    .PARAMETER Name
    The Name of the Resource vCenter

    .EXAMPLE
    Get-CXServiceVCDResourcevCenter -InfraConnectorId "bade10f4-bb71-41a3-8331-c1ce50375edd"

    Returns the all Resoruce vCenter objects for the site with the Id "8aed4131-5da4-48b0-a7d8-b5492a196455"

    .EXAMPLE
    Get-CXServiceVCDResourcevCenter -Name "LABVCSA1"

    Returns the Resoruce vCenter object with the Name "LABVCSA1"

    .NOTES
	  NAME: Get-CXServiceVCDResourcevCenter
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
	Param(
        [Parameter(Mandatory=$True, ParameterSetName = "ById")]
            [ValidateNotNullOrEmpty()] [string] $InfraConnectorId,
        [Parameter(Mandatory=$True, ParameterSetName = "ByName")]
            [ValidateNotNullOrEmpty()] [string] $Name
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Find the vCenter
    if($PSCmdlet.ParameterSetName -eq "ById"){
        [string] $URI = $global:DefaultCXServer.ServiceURI + "/mm/mgmt/sites/" + $InfraConnectorId + "/vcs/resource"
        $colResourcevCenter = Invoke-CXServiceAPIGet -URI $URI
        $colResourcevCenter
    }
    elseif($PSCmdlet.ParameterSetName -eq "ByName"){
        $vCloudInstances = Get-CXServiceVCDConfiguration
        $colResourcevCenter = ($vCloudInstances.ResourcevCenters | ?{$_.Name -eq $Name})
        if($colResourcevCenter -eq $null){
            throw "A Resoruce vCenter with the specified Name $Name cannot be found."
        } else{
            $colResourcevCenter
        }
    }
}

function Enable-CXServiceVCDResourcevCenter(){
    <#
    .SYNOPSIS
    Registers or updates an existing registration of a Resource vCenter for the vCloud Director Site with vCloud Extender

    .DESCRIPTION
    Registers or updates an existing registration of a Resource vCenter for the vCloud Director Site with vCloud Extender

    .PARAMETER Name
    The Name of the Resource vCenter

    .PARAMETER LookupServiceUrl
    The URI to the Lookup Service (eg. https://vcenter.fqdn/lookupservice/sdk")

    .PARAMETER Username
    The vSphere SSO Username (with administrative permissions) to connect with

    .PARAMETER Password
    The Password for the vSphere SSO User.

    .EXAMPLE
    Enable-CXServiceVCDResourcevCenter -Name "LABVCSA1" -LookupServiceUrl "https://labvc1.pigeonnuggets.com:443/lookupservice/sdk" -Username "administrator@vsphere.pigeonnuggets.com" -Password "Password"

    Registers the Resouce vCenter with the name LABVCSA1 using the provided Lookup Service and credentials.

    .EXAMPLE
    Enable-CXServiceVCDResourcevCenter -Name "LABVCSA1" -LookupServiceUrl "https://labvc2.pigeonnuggets.com:443/lookupservice/sdk" -Username "administrator2@vsphere.pigeonnuggets.com" -Password "Password"

    Updates the existing registration of the Resouce vCenter with the name LABVCSA1 with a new Lookup Service URI of https://labvc2.pigeonnuggets.com:443/lookupservice/sdk and a username of administrator2@vsphere.pigeonnuggets.com

    .NOTES
	  NAME: Enable-CXServiceVCDResourcevCenter
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)] [string] $Name,
        [Parameter(Mandatory=$True)] [string] $LookupServiceUrl,
        [Parameter(Mandatory=$True)] [string] $Username,
        [Parameter(Mandatory=$True)] [string] $Password
    )
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Find the vCenter
    $vCenter = Get-CXServiceVCDResourcevCenter -Name $Name
    if($vCenter.IsEnabled -eq $false){
        Write-Warning "The vCenter is currently already enabled. This cmdlet will update the registration. Do you wish to continue?" -WarningAction Inquire
        # Update the properties only
        $vCenter.lookupServiceUrl = $LookupServiceUrl
        $vCenter.adminUser.username = $Username
        $vCenter.adminUser.password = $Password
    } else {
        # Add the Lookup Service to the Object and update the username and password
        $vCenter | Add-Member Note* lookupServiceUrl $LookupServiceUrl
        $vCenter.adminUser.username = $Username
        $vCenter | Add-Member Note* type "vcenter"
        $vCenter.adminUser | Add-Member Note* password $Password
    }
    # Construct the JSON Payload and perform a HTTP PUT against the API Service
    [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mm/mgmt/sites/" + $vCenter.siteId + "/vcs/resource/" + $vCenter.Id + "?trust=true"
    Invoke-CXServiceAPIPut -Uri $URI -Data ($vCenter | Select type,id,name,url,adminUser,managedObjRef,infraManagerType,instanceUuid,siteId,lookupServiceUrl | ConvertTo-JSON)
}

function Add-CXServiceVCDConfiguration(){
    <#
    .SYNOPSIS
    Configures the vCloud Director instance for the vCloud Extender Cloud Service.

    .DESCRIPTION
    Configures the vCloud Director instance for the vCloud Extender Cloud Service.

    .PARAMETER Address
    The FQDN or IP address of the vCloud Director Cell.

    .PARAMETER SiteName
    A Site Name for the deployment

    .PARAMETER Username
    A user with administrator permissions on the System Org (eg. administrator)

    .PARAMETER Password
    The password for the user.

    .EXAMPLE
    Add-CXServiceVCDConfiguration -Address "vcd.pigeonnuggets.com" -SiteName "Berlin" -Username "administrator" -Password "Password!"

    Adds the vCloud Director cell/farm vcd.pigeonnuggets.com with a Site Name of "Berlin" using the credentials for the default System Administrator account.

    .NOTES
	  NAME: Add-CXServiceVCDConfiguration
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    Param(
        [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()] [string] $Address,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()] [string] $SiteName,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()] [string] $Username,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()] [string] $Password
    )
    # First test if we are connected
    if(!(Test-CXServiceEnvironment)){
		Break
    }
    # Next check if vCloud Site is not already registered to the CX Cloud Service
    $vCloudConfiguration = Get-CXServiceVCDConfiguration
    if($vCloudConfiguration -ne $null){
        Write-Warning "A vCloud Director instance is already registered to this CX Cloud Service. Only one registration is permitted per CX Cloud Service."
    } else {
        # Create the JSON Data Payload
        $objVCDService = New-Object System.Management.Automation.PSObject
        $objVCDService | Add-Member Note* ipAddress $Address
        $objVCDService | Add-Member Note* name $SiteName
        $objVCDService | Add-Member Note* orgName "System"
        $objVCDService | Add-Member Note* userName $Username
        $objVCDService | Add-Member Note* password $Password
        $objVCDService | Add-Member Note* targetInfraType "VCD"

        # Perform a HTTP POST against the API Service
        [string] $URI =  $global:DefaultCXServer.ServiceURI + "/mm/sites?trust=true"
        Invoke-CXServiceAPIPost -Uri $URI -Data ($objVCDService | ConvertTo-JSON)
    }
}

function Remove-CXServiceVCDConfiguration(){
    <#
    .SYNOPSIS
    Removes the currently configured vCloud Director instance from the configuration.

    .DESCRIPTION
    Removes the currently configured vCloud Director instance from the configuration.

    .EXAMPLE
    Remove-CXServiceVCDConfiguration

    Removes the currently configured vCloud Director from the configuration (and the assosiated Resource vCenter)

    .NOTES
	  NAME: Remove-CXServiceVCDConfiguration
	  AUTHOR: Adrian Begg
      LASTEDIT: 2018-05-22
    #>
    if(!(Test-CXServiceEnvironment -RequiredDeploymentType "cx-cloud-service")){
		Break
    }
    # Retrieve the current configuration
    $vCloudConfiguration = Get-CXServiceVCDConfiguration
    if($vCloudConfiguration.Count -eq 0){
        Write-Warning "There is currently no vCloud Director registered to this CX Cloud Service. No changes have been made."
    } else {
        # Warn the users that this is dangerous
        Write-Warning "This cmdlet removes the vCloud Director configuration from the CX Service Deployment. Are you sure you wish to continue." -WarningAction Inquire
        [string] $URI = $global:DefaultCXServer.ServiceURI + "/mm/sites/" + $vCloudConfiguration.InfraConnectorId
        $objDeleteResult = Invoke-CXServiceAPIDelete -URI $URI
        # TO DO: With the $objDeleteResult; track the progress of the running task
    }
}
#endregion
