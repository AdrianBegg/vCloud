##########################################################################################
# Name: Module-vCloud-RightsManagement.psm1
# Date: 26/03/2018 (v0.6)
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
#
# Purpose: PowerShell modules to extend the PowerCLI for vCloud to expose
# additional methods for management Organisation Rights which are currently not exposed
# via the vCloud GUI/PowerCLI cmdlets
#
# Ref: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf
################################################################################################################
# Change Log
# v0.1 - 6/05/2017 - Created module and tested on vCloud Director 8.20 and NSX 6.3
# v0.2 - 13/05/2017 - Added cmdlets for Adding and Removing single rights and amended API call behaviour
# v0.3 - 23/05/2017 - Rewriting the REST API base functions to leverage the existing $global:DefaultCIServers variable for connections rather then generating a session everytime and some error checking
# v0.4 - 12/07/2017 - Updating how the Org is obtained to use Get-Org to handle a ( and other reserverd char in a queries
# v0.5 - 16/09/2017:
# 	- Added cmdlets to expose hide/show OrgVDC for specific Org Users
#	- Cleaned up some error checking
#	- Updated cmdlet documentation
# v0.51 - 08/11/2017:
# 	- Moved the API Support Modules
# v0.6 - 26/03/2018:
# 	- Major Update for use with vCloud Director 9.1 (API Version 30); fixed Org Rights matching behaviour to match on URN not URL/RightsReference
##################################################################################################################

#region: API_Support_Functions
function Test-vCloudEnvironment(){
	<#
	.SYNOPSIS
	Performs some basic checks against the currently connected vCloud Director environment to determine if the current version is
	greater than the required version by a cmdlet and that there is a current connection active.

	.DESCRIPTION
	Performs some basic checks against the currently connected vCloud Director environment to determine if the current version is
	greater than the required version by a cmdlet and that there is a current connection active.

	Returns true if the test passes

	.PARAMETER Version
	The Minimum Version required by the cmdlet.

	.EXAMPLE
	Test-vCloudEnvironment -Version 8.20
	Will return true if connected to a vCloud Server with a version greater then "8.20"

	.EXAMPLE
	Test-vCloudEnvironment
	Will return true if connected to a vCloud Server (any version).
	.NOTES
	  NAME: Add-OrgVdcAccessRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-16
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$False)]
			[ValidateNotNullorEmpty()] [double] $Version
	)
	if(!$global:DefaultCIServers.IsConnected){
		throw "You are not currently connected to any servers. Please connect first using a Connect-CIServer cmdlet."
		$false
		Break
	} elseif((!([string]::IsNullOrEmpty($Version))) -and (!($global:DefaultCIServers.Version -gt $Version))){
		throw "The executing cmdlet requires the vCloud Director environment to be greater then $Version. The version of the connected server is $($global:DefaultCIServers.Version)"
		$false
		Break
	} else {
		$true
	}
}

function Get-vCloudAPIResponse(){
	<#
	.SYNOPSIS
	Wrapper function which returns the XML response from a vCloud Director API Call

	.DESCRIPTION
	Wrapper function which returns the XML response from a vCloud Director API Call

	.PARAMETER URI
	The URI of the vCloud API object to perform the GET request against

	.PARAMETER ContentType
	The Content-Type to pass to vCloud in the headers

	.EXAMPLE
	Get-vCloudAPIResponse -URI "https://vcd.pigeonnuggets.com/api/vApp/vm-f13ad1ca-3151-455c-aa84-935a2669da96/virtualHardwareSection/disks" -ContentType "application/vnd.vmware.vcloud.rasditemslist+xml"

	Returns the XML response from a HTTP GET to the API /virtualHardwareSection/disks section for object vm-f13ad1ca-3151-455c-aa84-935a2669da96 using the Session Key from the current connection and sets the content type to application/vnd.vmware.vcloud.rasditemslist+xml

	.NOTES
	  NAME: Get-vCloudAPIResponse
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware get vcloud director
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $ContentType
	)
	if(!(Test-vCloudEnvironment)){
		Break
	}
	# Setup Web Request for the API call to retireve the data from vCloud
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("x-vcloud-authorization",$global:DefaultCIServers.SessionSecret)
	$webclient.Headers.Add("Accept","application/*+xml;version=30.0")
	$webclient.Headers.Add("Content-Type", $ContentType)
	$webclient.Headers.Add("Accept-Language: en")
	try{
		[xml]$xmlResponse = $webclient.DownloadString($URI)
	} catch {
		throw "An error occured attempting to make HTTP GET against $URI"
	}
	$xmlResponse
}

function Publish-vCloudAPICall(){
	<#
	.SYNOPSIS
	Wrapper function which performs a PUT of XML to the vCloud Director API

	.DESCRIPTION
	Wrapper function which performs a PUT of XML to the vCloud Director API

	.PARAMETER URI
	The URI of the vCloud API object to perform the PUT request against

	.PARAMETER ContentType
	The Content-Type to pass to vCloud in the headers

	.PARAMETER Data
	The payload to PUT to the API

	.EXAMPLE
	Publish-vCloudAPICall -URI "https://vcd.pigeonnuggets.com/api/vApp/vm-f13ad1ca-3151-455c-aa84-935a2669da96/virtualHardwareSection/disks" -ContentType "application/vnd.vmware.vcloud.rasditemslist+xml" -Data $XMLOrgVDCSPConfig
	Peforms a HTTP PUT against vCloud Director URI https://vcd.pigeonnuggets.com/api/vApp/vm-f13ad1ca-3151-455c-aa84-935a2669da96/virtualHardwareSection/disks with the payload provided in the input variable $XMLOrgVDCSPConfig

	.NOTES
	  NAME: Publish-vCloudAPICall
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware publish vcloud director
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $ContentType,
		[Parameter(Mandatory=$True)] [xml] $Data
	)
	# Check if the server is connected
	if(!(Test-vCloudEnvironment)){
		Break
	}
	# Setup Web Request
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("x-vcloud-authorization",$global:DefaultCIServers.SessionSecret)
	$webclient.Headers.Add("Accept","application/*+xml;version=30.0")
	$webclient.Headers.Add("Content-Type", $ContentType)
	$webclient.Headers.Add("Accept-Language: en")

	# Convert the new configuration to byte array for upload
	[string] $strUploadData = $Data.OuterXml
	[byte[]]$byteArray = [System.Text.Encoding]::ASCII.GetBytes($strUploadData)
	# "To the cloud !"
	try{
		$UploadData = $webclient.UploadData($URI, "PUT", $bytearray)
	} catch {
		throw "An error occured attempting to make HTTP PUT against $URI"
	}
}

function Update-vCloudAPICall(){
	<#
	.SYNOPSIS
	Wrapper function which performs a POST of XML to the vCloud Director API

	.DESCRIPTION
	Wrapper function which performs a POST of XML to the vCloud Director API

	.PARAMETER URI
	The URI of the vCloud API object to perform the POST request against

	.PARAMETER ContentType
	The Content-Type to pass to vCloud in the headers

	.PARAMETER Data
	The payload to POST to the API

	.EXAMPLE
	Publish-vCloudAPICall -URI "https://vcd.pigeonnuggets.com/api/vApp/vm-f13ad1ca-3151-455c-aa84-935a2669da96/virtualHardwareSection/disks" -ContentType "application/vnd.vmware.vcloud.rasditemslist+xml" -Data $XMLOrgVDCSPConfig
	Peforms a HTTP POST against vCloud Director URI https://vcd.pigeonnuggets.com/api/vApp/vm-f13ad1ca-3151-455c-aa84-935a2669da96/virtualHardwareSection/disks with the payload provided in the input variable $XMLOrgVDCSPConfig

	.NOTES
	  NAME: Publish-vCloudAPICall
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware publish vcloud director
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $ContentType,
		[Parameter(Mandatory=$True)] [xml] $Data
	)
	# Check if the server is connected
	if(!(Test-vCloudEnvironment)){
		Break
	}
	# Setup Web Request
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("x-vcloud-authorization",$global:DefaultCIServers.SessionSecret)
	$webclient.Headers.Add("Accept","application/*+xml;version=30.0")
	$webclient.Headers.Add("Content-Type", $ContentType)
	$webclient.Headers.Add("Accept-Language: en")

	# Convert the new configuration to byte array for upload
	[string] $strUploadData = $Data.OuterXml
	[byte[]]$byteArray = [System.Text.Encoding]::ASCII.GetBytes($strUploadData)
	# "To the cloud !"
	try{
		$UploadData = $webclient.UploadData($URI, "POST", $bytearray)
	} catch {
		throw "An error occured attempting to make HTTP POST against $URI"
	}
}
#endregion

#region: XML Methods - Base methods for retreival and manipulation of XML from API
function Get-CIOrgRightsXML(){
	<#
	.SYNOPSIS
	Returns the base XML returend by the vCloud Director API for use by other methods for an Org

	.DESCRIPTION
	Returns the Org rights in vCloud for a provided orgnaisation

	.PARAMETER OrgName
	The Name of the vCloud Organisation

	.EXAMPLE
	Get-CIOrgRightsXML -OrgName "PigeonNuggets"

	Returns XML rights for the Org "PigeonNuggets"

	.NOTES
	  NAME: Get-CIOrgRightsXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware get vcloud director
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName
	)
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	# Retireve the Org object for the Organisation
	try{
		$Org = Get-Org -Name $OrgName | Get-CIView
	} catch {
		throw "Unable to find an Organisation $OrgName"
		Break
	}
	# Make the API call to get the Rights assigned
	[string] $URI = ($Org.Href + "/rights")
	[xml]$xmlOrgRights = Get-vCloudAPIResponse -URI $URI -ContentType "application/vnd.vmware.admin.org.rights+xml;version=30.0"

	# Return a the XML
	$xmlOrgRights
}

function Add-CIOrgRightXML(){
	<#
	.SYNOPSIS
	Adds a vCloud Right to the provided Organisation Org Right XML Document

	.DESCRIPTION
	Adds a single right to a vCloud Organisation and returns the XML to post back to the API. This can then be posted back to the API
	or more manipulation performed.

	.PARAMETER RightsXML
	The Rights for an Organisation in XML format

	.PARAMETER RightId
	The URN for the vCloud Right to be added

	.EXAMPLE
	Add-CIOrgRightXML -RightsXML $xmlReference -RightId "urn:vcloud:right:c53990c7-3932-3926-8247-45639243d734"

	.NOTES
	  NAME: Add-vCloudOrgRightXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware get vcloud director
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [xml] $RightsXML,
		[Parameter(Mandatory=$True)] [string] $RightId
	)
	# Create the RightReference URI for the provided Right
	try{
		$objRight = Get-CIView -Id $RightId
		$strRightId = $objRight.Id.Substring($objRight.Id.LastIndexOf(":")+1)
		$strNewRightReference = $RightsXML.OrgRights.href + "/" + $strRightId
	} catch {
		throw "Unable to resolve the right with the URN $RightId"
		Break
	}
	# First check if the right already exists
	if ($strNewRightReference -in $RightsXML.OrgRights.RightReference.Href){
		Write-Warning "The right with the URN $($RightId) is already assigned for this orgnaisation; no changes will be made."
		$RightsXML
	} else {

		# Load the XML and add the new element into the RightReference section
		[xml]$xmlRightsDoc = New-Object system.Xml.XmlDocument
		$xmlRightsDoc.LoadXml($RightsXML.OuterXml)

		$newRoleRight = $xmlRightsDoc.CreateElement("RightReference")
		$newRoleRight.SetAttribute("href",$strNewRightReference)
		$newRoleRight.SetAttribute("name",$objRight.Name)
		$newRoleRight.SetAttribute("type",$objRight.Type)
		$xmlRightsDoc.OrgRights.AppendChild($newRoleRight) > $nul

		# Get rid of the unwanted namespace element added by .NET and return to the caller
		$xmlRightsDoc = [xml] $xmlRightsDoc.OuterXml.Replace(" xmlns=`"`"", "")
		$xmlRightsDoc
	}
}
#endregion

#region: Public User Methods
function Get-CIRights(){
	<#
	.SYNOPSIS
	Returns a collection of the avaialble rights in the Global cloud infrastructure.

	.DESCRIPTION
	Returns a collection of the Global rights for the connected Cloud Infrastructure

	.NOTES
	  NAME: Get-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware get vcloud director
	  #Requires -Version 2.0
	#>
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	[string] $vCloudURI = $global:DefaultCIServers.ServiceUri.AbsoluteURI + "admin"
	$cloudRights = (Get-vCloudAPIResponse -URI $vCloudURI -ContentType "application/vnd.vmware.admin.vcloud+xml;version=30.0").VCloud.RightReferences.RightReference

	$colSystemRights = New-Object -TypeName System.Collections.ArrayList
	foreach($SystemRight in $cloudRights){
		$apiSystemRight = Get-vCloudAPIResponse $SystemRight.href -ContentType $SystemRight.type
		$objSystemRight = New-Object System.Management.Automation.PSObject
		$objSystemRight | Add-Member Note* Id $apiSystemRight.Right.id
		$objSystemRight | Add-Member Note* Name $apiSystemRight.Right.name
		$objSystemRight | Add-Member Note* Description $apiSystemRight.Right.Description
		$objSystemRight | Add-Member Note* href $apiSystemRight.Right.href
		$objSystemRight | Add-Member Note* Category $apiSystemRight.Right.Category
		$objSystemRight | Add-Member Note* Type $apiSystemRight.Right.type
		$colSystemRights.Add($objSystemRight) > $null
	}
	$colSystemRights
}

function Get-CIOrgRights(){
	<#
	.SYNOPSIS
	Returns a collection of the avaialble rights in the cloud and if they are enabled for the provided Org

	.DESCRIPTION
	Returns the Org rights in vCloud including any rights to vCloud Director Tenant Portal, and also from a new vCloud Director API for NSX which are not exposed through the GUI
	The collection returned will include all rights available with a property "Enabled"; if they are available to the Org this property will be true

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.EXAMPLE
	Get-CIOrgRights -OrgName "PigeonNuggets"

	Returns a collection of rights for the Org "PigeonNuggets" and if they are enabled

	.NOTES
	  NAME: Get-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  KEYWORDS: vmware get vcloud director
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName
	)
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	# Make the API call to get the Rights assigned
	try{
		[xml]$xmlOrgRights = Get-CIOrgRightsXML $OrgName
		# Next create a collection with the URNs (Id's) for each of the rights for reliable comparison
		$colOrgRights = New-Object -TypeName System.Collections.ArrayList
		foreach($xmlOrgRight in $xmlOrgRights.OrgRights.RightReference){
			$apiOrgRight = Get-vCloudAPIResponse $xmlOrgRight.href -ContentType $xmlOrgRights.OrgRights.type
			$objOrgRight = New-Object System.Management.Automation.PSObject
			$objOrgRight | Add-Member Note* Id $apiOrgRight.Right.id
			$objOrgRight | Add-Member Note* Name $apiOrgRight.Right.name
			$objOrgRight | Add-Member Note* Description $apiOrgRight.Right.Description
			$objOrgRight | Add-Member Note* href $apiOrgRight.Right.href
			$objOrgRight | Add-Member Note* Category $apiOrgRight.Right.Category
			$objOrgRight | Add-Member Note* Type $apiOrgRight.Right.type
			$colOrgRights.Add($objOrgRight) > $null
		}
	} catch {
		throw "Unable to get the Organisation Rights for $OrgName"
		Break
	}
	# Next we need to make a call to the API to resolve the Rights that are avaialble for the Cloud
	$cloudRights = Get-CIRights

	# Now build a collection of the rights available vs the rights enabled for the Organisation
	$colRights = New-Object -TypeName System.Collections.ArrayList
	foreach($objRight in $cloudRights){
		$objRightAssignment = New-Object System.Management.Automation.PSObject
		$objRightAssignment | Add-Member Note* Id $objRight.id
		$objRightAssignment | Add-Member Note* Name $objRight.name
		$objRightAssignment | Add-Member Note* Description $objRight.Description
		$objRightAssignment | Add-Member Note* Category $objRight.Category
		$objRightAssignment | Add-Member Note* Enabled ($objRight.id -in $colOrgRights.id)
		$colRights.Add($objRightAssignment) > $null
	}
	# Return a collection of rights
	$colRights
}

function Export-CIOrgRights(){
	<#
	.SYNOPSIS
	Exports the Org Rights for a provided vCloud Org to a CSV for manipulation externally

	.DESCRIPTION
	Outputs the rights assigned to an Org to a CSV file for all vCloud Rights assigned to the Org. This can then be manipulated and imported back into vCloud with new rights assignemtns using the Import-vCloudOrgRights cmdlet

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OutputFilePath
	A fully qualified path to for the file to output the generated CSV

	.EXAMPLE
	Export-CIOrgRights -OrgName "PigeonNuggets" -OutputFilePath "C:\_admin\Output.csv"

	Will write a CSV to C:\_admin\Output.csv containing a list of rights and for the vCloud tenancy and if they are enabled or not

	.NOTES
	  NAME: Export-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName,
		[Parameter(Mandatory=$True)] [string] $OutputFilePath
	)
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	# Check the Org Exists
	try{
		$Org = Get-Org -Name $OrgName | Get-CIView
	} catch {
		throw "Unable to find an Organisation $OrgName"
		Break
	}
	Get-CIOrgRights -OrgName $OrgName | Export-CSV $OutputFilePath -NoTypeInformation
}

function Import-CIOrgRights(){
	<#
	.SYNOPSIS
	Imports a set of vCloud Director Rights from a provided CSV

	.DESCRIPTION
	Will replace the Org rights enabled on a vCloud Organisation with those from a CSV containing the roles in the format name,enabled (role name, true/false)

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER InputCSVFile
	A fully qualified path to for the input CSV file which will be applied to the Organisation

	.EXAMPLE
	Import-CIOrgRights -OrgName "PigeonNuggets" -InputCSVFile "C:\Temp\Rules.csv"

	Will overwrite the OrgRights assigned to the Org PigeonNuggets with the ones defined as enabled in the CSV "C:\Temp\Rules.csv"

	.NOTES
	  NAME: Import-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName,
		[Parameter(Mandatory=$True)] [string] $InputCSVFile
	)
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	# Check if the CSV provided exists
	if(!(Test-Path $InputCSVFile)){
		throw "The file $InputCSVFile does not exist. Please check the path and try again."
		Break
	}
	try{
		$Org = Get-Org -Name $OrgName | Get-CIView
	} catch {
		throw "Unable to find an Organisation $OrgName"
		Break
	}
	# Import the rules from the CSV and get a list of valid rights for the Org
	$colRightsCSV = Import-CSV -Path $InputCSVFile
	$colEnabledRights = $colRightsCSV | ?{$_.enabled.ToLower() -eq "true"}
	# Get the existing Org Rights XML
	[xml] $xmlOrgRights = Get-CIOrgRightsXML $OrgName

	# First clean the existing configuration of all OrgRights
	[xml]$xmlRightsDoc = New-Object system.Xml.XmlDocument
	$xmlRightsDoc.LoadXml($xmlOrgRights.OuterXml)
	foreach($OrgRight in $xmlRightsDoc.OrgRights.RightReference){
		$xmlRightsDoc.OrgRights.RemoveChild($OrgRight) > $nul
	}
	# Get the rights for the current vCloud instance
	$cloudRights = Get-CIRights
	$newOrgRights = $cloudRights | ?{$_.id -in $colEnabledRights.id}

	# Add the rights from the CSV into the configuration file stripped of the existing rights
	foreach($appliedRight in $newOrgRights){
		$xmlRightsDoc = Add-CIOrgRightXML -RightsXML $xmlRightsDoc -RightId $appliedRight.id
	}
	# Retireve the Org object for the Organisation
	try{
		$Org = Get-Org -Name $OrgName | Get-CIView
		# Make the API call to POST the Rights assigned
		[string] $URI = ($Org.Href + "/rights")
		Publish-vCloudAPICall -URI $URI -ContentType "application/vnd.vmware.admin.org.rights+xml;version=30.0" -Data $xmlRightsDoc
	} catch {
		throw "An error occured applying the imported rights to the Org $OrgName."
	}
}

function Remove-CIOrgRight(){
	<#
	.SYNOPSIS
	Removes a single vCloud Director right from an Organisation

	.DESCRIPTION
	Removes a single vCloud Director right from an Organisation

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER Right
	The name of the vCloud Director right to remove from the Organisation

	.EXAMPLE
	Remove-CIOrgRight -OrgName "PigeonNuggets" -Right "vApp Template / Media: Edit"

	Removes the right "vApp Template / Media: Edit" to the Organisation PigeonNuggets if it is enabled

	.NOTES
	  NAME: Remove-CIOrgRight
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2018-03-26
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName,
		[Parameter(Mandatory=$True)] [string] $Right
	)
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	# Check if the OrgRight is currently enabled for the Org
	$colOrgRights = (Get-CIOrgRights $OrgName) | ?{$_.enabled -eq $true}
	if (($colOrgRights | ?{$_.name -in $Right}) -eq $null){
		Write-Warning "The Org Right $Right is not currently enabled on Org $OrgName no changes have been made."
	} else {
		# Get the current rights and remove the right from the configuration
		[xml]$xmlOrgRights = Get-CIOrgRightsXML $OrgName
		[xml]$xmlRightsDoc = New-Object system.Xml.XmlDocument
		$xmlRightsDoc.LoadXml($xmlOrgRights.OuterXml)
		# Now iterate through and find the Org Right
		foreach($OrgRight in $xmlRightsDoc.OrgRights.RightReference){
			if($OrgRight.Name -eq $Right){
				$xmlRightsDoc.OrgRights.RemoveChild($OrgRight) > $nul
			}
		}
		# Make the API call to POST the Rights assigned
		try{
			# Retireve the Org object for the Organisation
			$Org = Get-Org -Name $OrgName | Get-CIView
			[string] $URI = ($Org.Href + "/rights")
			Publish-vCloudAPICall -URI $URI -ContentType "application/vnd.vmware.admin.org.rights+xml;version=30.0"	-Data $xmlRightsDoc
		} catch {
			throw "An error occured removing the right $Right from Org $OrgName."
		}
	}
}

function Add-CIOrgRight(){
	<#
	.SYNOPSIS
	Adds a single vCloud Director right to an Organisation

	.DESCRIPTION
	Adds the provided vCloud Director right to the specfied Organisation

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER Right
	The name of the vCloud Director right to assign

	.EXAMPLE
	Add-CIOrgRight -OrgName "PigeonNuggets" -Right "vApp Template / Media: Edit"

	Adds the right "vApp Template / Media: Edit" to the Organisation PigeonNuggets if not already enabled

	.NOTES
	  NAME: Add-CIOrgRight
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-24
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName,
		[Parameter(Mandatory=$True)] [string] $Right
	)
	# Check if the server is connected and version is greater then 8.20
	if(!(Test-vCloudEnvironment -Version 8.20)){
		Break
	}
	# Check if the OrgRight is currently enabled for the Org
	$colOrgRights = (Get-CIOrgRights $OrgName) | ?{$_.enabled -eq $true}
	if (!(($colOrgRights | ?{$_.name -in $Right}) -eq $null)){
		Write-Warning "The Org Right $Right already exists for Org $OrgName no changes have been made."
	} else {
		# Get the current rights and add the new right to the configuration
		[xml]$xmlOrgRights = Get-CIOrgRightsXML $OrgName
		# Match the Rights Reference from the Global Rights list
		$cloudRights = Get-CIRights
		$newOrgRight = $cloudRights | ?{$_.name -in $Right}
		if($newOrgRight -ne $null){
			$xmlNewRightsDoc = Add-CIOrgRightXML -RightsXML $xmlOrgRights -RightId $newOrgRight.id
		} else {
			throw "Unable to find a right with the name $Right to add to the Organisation. Please verify the right name and try again."
		}

		# Make the API call to POST the newly added Right
		try{
			$Org = Get-Org -Name $OrgName | Get-CIView
			[string] $URI = ($Org.Href + "/rights")
			Publish-vCloudAPICall -URI $URI -ContentType "application/vnd.vmware.admin.org.rights+xml;version=30.0" -Data $xmlNewRightsDoc
		} catch {
			throw "An error occured adding the new right $Right to the Org $OrgName."
		}
	}
}
#endregion

#region: Org VDC View Rights
function Get-OrgVdcAccessRightsXML(){
	<#
	.SYNOPSIS
	Support function which returns the Access Controls for a provided Organisation Virtual Datacenter object in XML from the vCloud API.

	.DESCRIPTION
	Returns the XML returned by an API call to vCloud for a OrgVDC with the Provided ID.

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC to query

	.EXAMPLE
	Get-OrgVdcAccessRightsXML -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8"

	Returns the AccessControl details in XML format for the Org VDC with the Id urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8

	.NOTES
	  NAME: Get-OrgVdcAccessRightsXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-13
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId
	)
	# The controlAccess is not exposed in the AdminView of object (the deafult reutnred from Get-OrgVDC) need to get the User View Level
	$objOrgVDCUserView = Get-CIView -Id $OrgVDCId -ViewLevel User
	[string] $OrgVDCURI = $objOrgVDCUserView.Href
	[xml]$XMLOrgVDCResponse = (Get-vCloudAPIResponse -URI $OrgVDCURI -ContentType "application/vnd.vmware.vcloud.vdc+xml")
	# Next retireve the Access Control information currently set for the OrgVDC; get the URI for the current AccessControl
	[string] $AccessControlURI = ($XMLOrgVDCResponse.Vdc.Link | ?{(($_.rel -eq "down") -and ($_.type -eq "application/vnd.vmware.vcloud.controlAccess+xml"))}).href
	[xml]$XMLOrgVDCAccessRights = (Get-vCloudAPIResponse -URI $AccessControlURI -ContentType "application/vnd.vmware.vcloud.controlAccess+xml")
	# Return to the caller
	$XMLOrgVDCAccessRights
}

function Update-OrgVDCAccessRightsXML(){
	<#
	.SYNOPSIS
	Support function which performs a PUT against a provided Organisation Virtual Datacenter to update the Access Controls elements via the vCloud API.

	.DESCRIPTION
	Support function which performs a HTTP PUT of the provided XML against vCloud for a OrgVDC with the Provided ID to update the Access Controls elements.

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC to query

	.PARAMETER AccessControlData
	Well formed XML to post against the /action/controlAccess/ of the OrgVDC

	.EXAMPLE
	Update-OrgVdcAccessRightsXML -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" -AccessControlData $xmlObject

	Makes a HTTP PUT against the controlAccess link of the Org VDC Id urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8 with the data payload of $xmlObject.

	.NOTES
	  NAME: Update-OrgVdcAccessRightsXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-14
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId,
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [xml] $AccessControlData
	)
	# The controlAccess is not exposed in the AdminView of object (the deafult reutnred from Get-OrgVDC) need to get the User View Level
	$objOrgVDCUserView = Get-CIView -Id $OrgVDCId -ViewLevel User
	[string] $OrgVDCURI = $objOrgVDCUserView.Href
	[xml]$XMLOrgVDCResponse = (Get-vCloudAPIResponse -URI $OrgVDCURI -ContentType "application/vnd.vmware.vcloud.vdc+xml")
	# Next retireve the Access Control URI to update for the OrgVDC
	[string] $AccessControlURI = ($XMLOrgVDCResponse.Vdc.Link | ?{(($_.rel -eq "controlAccess") -and ($_.type -eq "application/vnd.vmware.vcloud.controlAccess+xml"))}).href
	# Make the call against the API to update the object
	try{
		Publish-vCloudAPICall -URI $AccessControlURI -ContentType "application/vnd.vmware.vcloud.controlAccess+xml"	-Data $AccessControlData
	} catch {
		throw "An error occured updating the Access Control data for the Organisation."
	}
}

function Get-OrgVdcAccessRights(){
	<#
	.SYNOPSIS
	Returns the Access Controls for a provided Organisation Virtual Datacenter object.

	.DESCRIPTION
	Returns the Access Controls for a provided Organisation Virtual Datacenter object. Upon creation, an organization VDC grants full access to all members of the containing organization however an administrator can use an access control mechanism to restrict access to specific users.

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OrgVDC
	The name of the Organization Virtual Datacenter to query

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC

	.EXAMPLE
	Get-OrgVdcAccessRights -OrgName "PigeonNuggets"

	Returns a collection of objects containing the Access Controls currently applied to all VDC's in the Organisation "PigeonNuggets"

	.EXAMPLE
	Get-OrgVdcAccessRights -OrgName "PigeonNuggets" -OrgVDC "Production"

	Returns an object containing the Access Controls currently applied to the Org VDC "Production" in the Organisation "PigeonNuggets"

 	.EXAMPLE
	Get-OrgVdcAccessRights -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8"

	Returns the AccessControl details for the Org VDC with the Id urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8

	.NOTES
	  NAME: Get-OrgVdcAccessRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-12
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgName,
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgVDC,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId
	)
	# TODO: Add Support for External User objects (No SSO in the Lab at the moment further testing required)
	# Check if the server is connected and version is greater then 8.10
	if(!(Test-vCloudEnvironment -Version 8.10)){
		Break
	}
	# Check if OrgVDC paramter has been provided and query to return the collection of OrgVdc Objects
	try{
		if(!([string]::IsNullOrEmpty($OrgVDCId))){
			$colOrgVDC = (Get-OrgVDC -Id $OrgVDCId)
		} elseif(!([string]::IsNullOrEmpty($OrgVDC))){
			$colOrgVDC = (Get-OrgVdc -Name $OrgVDC -Org $OrgName)
		} else {
			$colOrgVDC = (Get-OrgVdc -Org $OrgName)
		}
	} catch {
		throw "Unable to find an Org VDC matching the provided criteria; please check the provided values and try again."
	}
	# A collection of the OrgVDC Access Rights Objects
	$colOrgVDCRights = New-Object -TypeName System.Collections.ArrayList
	foreach($objOrgVDC in $colOrgVDC){
		# Retreive the Access Control information set for the OrgVDC
		[xml]$OrgVDCAccessRights = Get-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDC.Id
		# Create a PSObject with the properties
		$objVDCAccessRight = New-Object System.Management.Automation.PSObject
		$objVDCAccessRight | Add-Member Note* Organization $objOrgVDC.Org
		$objVDCAccessRight | Add-Member Note* OrgVDC $objOrgVDC
		$objVDCAccessRight | Add-Member Note* IsSharedToEveryone $OrgVDCAccessRights.ControlAccessParams.IsSharedToEveryone
		if(!([string]::IsNullOrEmpty($OrgVDCAccessRights.ControlAccessParams.EveryoneAccessLevel))){
			$objVDCAccessRight | Add-Member Note* EveryoneAccessLevel $OrgVDCAccessRights.ControlAccessParams.EveryoneAccessLevel
		} else {
			$objVDCAccessRight | Add-Member Note* EveryoneAccessLevel "NoAccess"
		}
		# A collection of Access Settings
		$colVDCAccessSettings = New-Object -TypeName System.Collections.ArrayList
		foreach($AccessSetting in $OrgVDCAccessRights.ControlAccessParams.AccessSettings.AccessSetting){
			$objVDCAccessSetting = New-Object System.Management.Automation.PSObject
			# Get the Local VDC User and retireve the CIUser Object for the user
			if($AccessSetting.Subject -ne $null){
				$CIUserObj = Get-CIUser -Id ((Get-vCloudAPIResponse -URI $AccessSetting.Subject.href -ContentType $AccessSetting.Subject.Type).User.Id)
				$objVDCAccessSetting | Add-Member Note* CIUser $CIUserObj
				$objVDCAccessSetting | Add-Member Note* AccessLevel $AccessSetting.AccessLevel
				$colVDCAccessSettings.Add($objVDCAccessSetting) > $null
			}
		}
		$objVDCAccessRight | Add-Member Note* AccessSettings $colVDCAccessSettings
		$colOrgVDCRights.Add($objVDCAccessRight) > $null
	}
	# Return a collection of Access Rights for the targetted VDC's
	$colOrgVDCRights
}

function Set-OrgVdcAccessRightSharedToEveryone(){
	<#
	.SYNOPSIS
	Set or reset the flag for the provided Organisation Virtual Datacenter object to be visible to all users.

	.DESCRIPTION
	This cmdlet sets an Organisation Virtual Datacenter as visible or hidden for all users who have rights to the organisation. By default an Org VDC is visible to all members of the containing organization; if the -Visible:$false is provided the org VDC will be hidden from all users by default. If -Visible:$true is set it will be visible to all users by default.

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OrgVDC
	The name of the Organization Virtual Datacenter to query

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC

	.PARAMETER Visible
	Default: True
	If set to $True will reset the Org VDC to visible to all users, if $False the OrgVDC will be hidden for all users

	.EXAMPLE
	Set-OrgVdcAccessRightSharedToEveryone -OrgName "PigeonNuggets" -OrgVDC "Production" -Visible $false

	Sets the Access Control applied to the Org VDC "Production" in the Organisation "PigeonNuggets" to hidden by default.
	The Org VDC will only be visible to users that have been added using Add-OrgVdcAccessRights cmdlet.

	.EXAMPLE
	Set-OrgVdcAccessRightSharedToEveryone -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" -Visible $false

	Sets the Access Control applied to the Org VDC with the vCloud Object Id "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8"
	to hidden by default. The Org VDC will only be visible to users that have been added using Add-OrgVdcAccessRights cmdlet.

	.EXAMPLE
	Set-OrgVdcAccessRightSharedToEveryone -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" -Visible $true

	Resets the Access Control applied to the Org VDC with the vCloud Object Id "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8"
	to make the object visible by default.

	.EXAMPLE
	Set-OrgVdcAccessRightSharedToEveryone -OrgName "PigeonNuggets" -OrgVDC "Production" -Visible $true

	Resets the default Access Control applied to the Org VDC "Production" in the Organisation "PigeonNuggets" to visible by default.
	The Org VDC will be visible to all users.

	.NOTES
	  NAME: Set-OrgVdcAccessRightSharedToEveryone
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-12
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgVDC,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId,
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[bool] $Visible = $true
	)
	# Check if the server is connected and version is greater then 8.10
	if(!(Test-vCloudEnvironment -Version 8.10)){
		Break
	}
	# Check if OrgVDCId paramter has been provided or the Orgname and get the current specification
	if(!([string]::IsNullOrEmpty($OrgVDCId))){
		$objOrgVDCAccessControl = Get-OrgVdcAccessRights -OrgVDCId $OrgVDCId
	} else {
		$objOrgVDCAccessControl = Get-OrgVdcAccessRights -OrgName $OrgName -OrgVDC $OrgVDC
	}
	# Check the current status of the default AccessControl on the OrgVDC
	if($Visible -and ($objOrgVDCAccessControl.IsSharedToEveryone -eq $true)){
		Write-Warning "The OrgVDC provided is already set to be visible to all users by default. No changes have been made."
		Break
	} elseif(!$Visible -and ($objOrgVDCAccessControl.IsSharedToEveryone -eq $false)){
		Write-Warning "The OrgVDC provided is already set to be hidden to all users by default. No changes have been made."
		Break
	} else {
		# Load the current XML configuration for update
		[xml]$xmlOrgVDCAccessRights = Get-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDCAccessControl.OrgVDC.Id
		# Update the IsSharedToEveryone attribute; has to be in lowercase or 400 Bad Request is thrown
		$xmlOrgVDCAccessRights.ControlAccessParams.IsSharedToEveryone = ($Visible.ToString()).ToLower()
		# Add/Update the EveryoneAccessLevel element if visible has been set
		if($Visible){
			# Check if the EveryoneAccessLevel element is present/exists
			if([string]::IsNullOrEmpty($xmlOrgVDCAccessRights.ControlAccessParams.EveryoneAccessLevel)){
				[Xml.XmlNode] $xmlEveryOneAccessLevel = $xmlOrgVDCAccessRights.CreateNode("element","EveryoneAccessLevel","");
				$xmlEveryOneAccessLevel.InnerText = "ReadOnly"
				# The Node needs to be ordered immediately after the IsSharedToEveryone Element
				$xmlNodeSharedEveryone = $xmlOrgVDCAccessRights.ControlAccessParams.GetElementsByTagName("IsSharedToEveryone")[0]
				$xmlOrgVDCAccessRights.ControlAccessParams.InsertAfter($xmlEveryOneAccessLevel,$xmlNodeSharedEveryone) > $nul
				# Get rid of the unwanted namespace element added by .NET and return to the caller
				$xmlOrgVDCAccessRights = [xml] $xmlOrgVDCAccessRights.OuterXml.Replace(" xmlns=`"`"", "")
			} else {
				# If it already exists update the value
				$xmlOrgVDCAccessRights.ControlAccessParams.EveryoneAccessLevel = "ReadOnly" > $nul
			}
		}
		# Make the update via an API call
		Update-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDCAccessControl.OrgVDC.Id -AccessControlData $xmlOrgVDCAccessRights
	}
}

function Remove-OrgVdcAccessRights(){
	<#
	.SYNOPSIS
	Revokes a vCloud User Rights to Read an Organisation Virtual Datacenter object which has been hidden from users by default.

	.DESCRIPTION
	This cmdlet removes a CIUser from the Access Control List for an Organisation Virtual Datacenter. If the Organisation has been hidden using the Set-OrgVdcAccessRightSharedToEveryone cmdlet the users removed using this cmdlet will no longer have rights to access/view the Organisational VDC. By default an Org VDC is visible to all members of the containing organization.

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OrgVDC
	The name of the Organization Virtual Datacenter to query

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC

	.PARAMETER User
	A CIUser object to remove/revoke rights to View the VDC if hidden

	.EXAMPLE
	Remove-OrgVdcAccessRights -OrgName "PigeonNuggets" -OrgVDC "Production" -User $CIUser

	Sets the Access Control applied to the Org VDC "Production" in the Organisation "PigeonNuggets" to deny user $CIUser access it if it is hidden by the Set-OrgVdcAccessRightSharedToEveryone cmdlet.

	.EXAMPLE
	Remove-OrgVdcAccessRights -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" -User $CIUser

	Sets the Access Control applied to the Org VDC with the vCloud Object Id "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" to deny user $CIUser access it if it is hidden by the Set-OrgVdcAccessRightSharedToEveryone cmdlet.

	.NOTES
	  NAME: Remove-OrgVdcAccessRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-14
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgVDC,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId,
		[Parameter(Mandatory=$True,ParameterSetName = "ByName",ValueFromPipeline=$True)]
		[Parameter(Mandatory=$True,ParameterSetName = "ById",ValueFromPipeline=$True)]
			[ValidateNotNullorEmpty()]  [PSObject] $User
	)
	# Check if the server is connected and version is greater then 8.10
	if(!(Test-vCloudEnvironment -Version 8.10)){
		Break
	}
	# Check if OrgVDCId paramter has been provided or the Orgname and get the current specification
	if(!([string]::IsNullOrEmpty($OrgVDCId))){
		$objOrgVDCAccessControl = Get-OrgVdcAccessRights -OrgVDCId $OrgVDCId
	} else {
		$objOrgVDCAccessControl = Get-OrgVdcAccessRights -OrgName $OrgName -OrgVDC $OrgVDC
	}
	# Check if the user object provided has an access right present in the OrgVDC
	if(($objOrgVDCAccessControl.AccessSettings.CIUser | ?{$_ -eq $User}) -eq $null){
		Write-Warning "The User $($User.Name) currently does not have explicit rights defined on the OrgVDC $($objOrgVDCAccessControl.OrgVDC.Name); no changes have been made."
		Break
	} else {
		# Load the current XML configuration for update
		[xml]$xmlOrgVDCAccessRights = Get-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDCAccessControl.OrgVDC.Id
		# Find the node and remove it from the XML
		[Xml.XmlElement] $xmlUserToRemove = $XMLOrgVDCAccessRights.ControlAccessParams.AccessSettings.AccessSetting | ?{$_.Subject.href -eq $User.href}
		$xmlOrgVDCAccessRights.ControlAccessParams.AccessSettings.RemoveChild($xmlUserToRemove) > $nul
		# Check if this is the last user in the AccessSettings ACL and remove the node if required
		if($XMLOrgVDCAccessRights.ControlAccessParams.AccessSettings.AccessSetting -eq $null){
			$XMLOrgVDCAccessRights.ControlAccessParams.RemoveChild($XMLOrgVDCAccessRights.ControlAccessParams.GetElementsByTagName("AccessSettings")[0]) > $nul
			# If the IsSharedEveryone is set to $false; for the last user removed the "EveryoneAccessLevel" element must be provided in the API PUT
			if($xmlOrgVDCAccessRights.ControlAccessParams.IsSharedToEveryone -eq "false"){
				if([string]::IsNullOrEmpty($xmlOrgVDCAccessRights.ControlAccessParams.EveryoneAccessLevel)){
					[Xml.XmlNode] $xmlEveryOneAccessLevel = $xmlOrgVDCAccessRights.CreateNode("element","EveryoneAccessLevel","");
					$xmlEveryOneAccessLevel.InnerText = "ReadOnly"
					# The Node needs to be ordered immediately after the IsSharedToEveryone Element
					$xmlNodeSharedEveryone = $xmlOrgVDCAccessRights.ControlAccessParams.GetElementsByTagName("IsSharedToEveryone")[0]
					$xmlOrgVDCAccessRights.ControlAccessParams.InsertAfter($xmlEveryOneAccessLevel,$xmlNodeSharedEveryone) > $nul
					# Get rid of the unwanted namespace element added by .NET and return to the caller
					$xmlOrgVDCAccessRights = [xml] $xmlOrgVDCAccessRights.OuterXml.Replace(" xmlns=`"`"", "")
				}
			}
		}
		# Make the update to the OrgVDC via an API call
		Update-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDCAccessControl.OrgVDC.Id -AccessControlData $xmlOrgVDCAccessRights
	}
}

function Add-OrgVdcAccessRights(){
	<#
	.SYNOPSIS
	Grants a vCloud User Rights to Read an Organisation Virtual Datacenter object which has been hidden from users by default.

	.DESCRIPTION
	This cmdlet adds a CIUser to the Access Control for an Organisation Virtual Datacenter. If the Organisation has been hidden using the Set-OrgVdcAccessRightSharedToEveryone cmdlet the users added using this cmdlet can access/view the Organisational VDC. By default an Org VDC is visible to all members of the containing organization.

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OrgVDC
	The name of the Organization Virtual Datacenter to query

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC

	.PARAMETER User
	A CIUser object to add to Grant rights to View the VDC if hidden

	.EXAMPLE
	Add-OrgVdcAccessRights -OrgName "PigeonNuggets" -OrgVDC "Production" -User $CIUser

	Sets the Access Control applied to the Org VDC "Production" in the Organisation "PigeonNuggets" to allow user $CIUser access it if it is hidden by the Set-OrgVdcAccessRightSharedToEveryone cmdlet.

	.EXAMPLE
	Add-OrgVdcAccessRights -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" -User $CIUser

	Sets the Access Control applied to the Org VDC with the vCloud Object Id "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8" to allow user $CIUser access it if it is hidden by the Set-OrgVdcAccessRightSharedToEveryone cmdlet.

	.NOTES
	  NAME: Add-OrgVdcAccessRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-14
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.197
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgName,
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgVDC,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId,
		[Parameter(Mandatory=$True,ParameterSetName = "ByName",ValueFromPipeline=$True)]
		[Parameter(Mandatory=$True,ParameterSetName = "ById",ValueFromPipeline=$True)]
			[ValidateNotNullorEmpty()]  [PSObject] $User
	)
	# TO DO: Add support for External User Types
	# Check if the server is connected and version is greater then 8.10
	if(!(Test-vCloudEnvironment -Version 8.10)){
		Break
	}
	# Check if OrgVDCId paramter has been provided or the Orgname and get the current specification
	if(!([string]::IsNullOrEmpty($OrgVDCId))){
		$objOrgVDCAccessControl = Get-OrgVdcAccessRights -OrgVDCId $OrgVDCId
	} else {
		$objOrgVDCAccessControl = Get-OrgVdcAccessRights -OrgName $OrgName -OrgVDC $OrgVDC
	}
	# Check the current status of the default AccessControl on the OrgVDC
	if($objOrgVDCAccessControl.IsSharedToEveryone -eq $true){
		Write-Warning "The OrgVDC provided is currently set to be visible to all users by default. The Access Rights have been changed however have no effect until the Set-OrgVdcAccessRightSharedToEveryone is run to hide the Org VDC."
	}
	# Check if the user currently already has rights; do nothing if they do
	if(($objOrgVDCAccessControl.AccessSettings | ?{$_.CIUser -eq $User}) -ne $null){
		Write-Warning "The User $User.Name currently already has been granted rights to the OrgVDC; no changes will be made."
	} else {
		# Load the current XML configuration for update
		[xml]$xmlOrgVDCAccessRights = Get-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDCAccessControl.OrgVDC.Id

		# Next add a new AccessSetting node with the properties for the CIUser object under "AccessSettings"
		$CIUserView = $User | Get-CIView
		# Construct a new AccessSetting Node for the user object
		[Xml.XmlNode] $xmlUserAccessSettingNode = $xmlOrgVDCAccessRights.CreateNode("element","AccessSetting","")

		# Create the Subject of the Access Right
		[Xml.XmlElement] $newAccessRightUser = $xmlOrgVDCAccessRights.CreateElement("Subject")
		$newAccessRightUser.SetAttribute("href",$CIUserView.href) > $nul
		$newAccessRightUser.SetAttribute("name",$CIUserView.Name) > $nul
		$newAccessRightUser.SetAttribute("type",$CIUserView.Type) > $nul
		# Add the Access Level to the Access Right
		[Xml.XmlNode] $xmlAccessLevel = $xmlOrgVDCAccessRights.CreateNode("element","AccessLevel","");
		$xmlAccessLevel.InnerText = "ReadOnly"

		$xmlUserAccessSettingNode.AppendChild($newAccessRightUser) > $nul
		$xmlUserAccessSettingNode.AppendChild($xmlAccessLevel) > $nul

		# Now insert the AccessSetting into the AccessSettings Node; if it doesnt exist create it
		if($xmlOrgVDCAccessRights.ControlAccessParams.AccessSettings -eq $null){
			# Create the node "AccountSettings "and add the new user element an commit it to XML
			[Xml.XmlNode] $xmlAccessSettingsNode = $xmlOrgVDCAccessRights.CreateNode("element","AccessSettings","")
			$xmlAccessSettingsNode.AppendChild($xmlUserAccessSettingNode) > $nul
			$xmlOrgVDCAccessRights.ControlAccessParams.AppendChild($xmlAccessSettingsNode) > $nul
		} else {
			# Add the node to the existing user list at the tail
			$xmlOrgVDCAccessRights.ControlAccessParams.AccessSettings.AppendChild($xmlUserAccessSettingNode) > $nul
		}
		# Get rid of the unwanted namespace element added by .NET and return to the caller
		$xmlOrgVDCAccessRights = [xml] $xmlOrgVDCAccessRights.OuterXml.Replace(" xmlns=`"`"", "")
		# Make the update via an API call
		Update-OrgVdcAccessRightsXML -OrgVDCId $objOrgVDCAccessControl.OrgVDC.Id -AccessControlData $xmlOrgVDCAccessRights
	}
}
#endregion
