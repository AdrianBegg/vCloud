##########################################################################################
# Name: Module-vCloud-RightsManagement.psm1
# Date: 11/05/2017 (v0.1)
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
# 
# Purpose: PowerShell modules to extend the PowerCLI for vCloud to expose
# additional methods for management Organisation Rights which are currently not exposed
# via the vCloud GUI/PowerCLI cmdlets
#
# Ref: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf 
##########################################################################################
# Change Log
# v0.1 - 11/05/2017 - Created module and tested on vCloud Director 8.20 and NSX 6.3
##########################################################################################

#region: API_Support_Functions
function Get-vCloudAPIResponse(){
	<#
	.SYNOPSIS
	Wrapper function which returns the XML response from a vCloud Director API Call

	.DESCRIPTION
	Wrapper function which returns the XML response from a vCloud Director API Call

	.PARAMETER URI
	The URI of the vCloud API object to perform the GET request against

	.PARAMETER SessionKey
	The SessionKey to use for authentication

	.PARAMETER ContentType
	The Content-Type to pass to vCloud in the headers

	.EXAMPLE
	Get-vCloudAPIResponse -URI "https://vcd.pigeonnuggets.com/api/vApp/vm-f13ad1ca-3151-455c-aa84-935a2669da96/virtualHardwareSection/disks" -SessionKey "850a11b158434697a750f31d50c857d4" -ContentType "application/vnd.vmware.vcloud.rasditemslist+xml"

	Returns the XML response from a HTTP GET to the API /virtualHardwareSection/disks section for object vm-f13ad1ca-3151-455c-aa84-935a2669da96 using the Session Key 850a11b158434697a750f31d50c857d4 and sets the content type to application/vnd.vmware.vcloud.rasditemslist+xml

	.NOTES
	  NAME: Get-vCloudAPIResponse
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-05
	  KEYWORDS: vmware get vcloud director 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $SessionKey,
		[Parameter(Mandatory=$True)] [string] $ContentType
	)	
	# Setup Web Request for the API call to retireve the data from vCloud
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("x-vcloud-authorization",$SessionKey)
	$webclient.Headers.Add("Accept","application/*+xml;version=27.0")
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
	Wrapper function which performs a POST of XML to the vCloud Director API

	.DESCRIPTION
	Wrapper function which performs a POST of XML to the vCloud Director API

	.PARAMETER URI
	The URI of the vCloud API object to perform the POST request against

	.PARAMETER SessionKey
	The SessionKey to use for authentication

	.PARAMETER ContentType
	The Content-Type to pass to vCloud in the headers
	
	.PARAMETER Data
	The payload to POST to the API

	.EXAMPLE
	
	.NOTES
	  NAME: Publish-vCloudAPICall
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11
	  KEYWORDS: vmware publish vcloud director 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $URI,
		[Parameter(Mandatory=$True)] [string] $SessionKey,
		[Parameter(Mandatory=$True)] [string] $ContentType,
		[Parameter(Mandatory=$True)] [xml] $Data
	)
	# Setup Web Request
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("x-vcloud-authorization",$SessionKey)
	$webclient.Headers.Add("Accept","application/*+xml;version=27.0")
	$webclient.Headers.Add("Content-Type", $ContentType)
	$webclient.Headers.Add("Accept-Language: en")
	
	# Convert the new configuration to byte array for upload
	[string] $strUploadData = $Data.OuterXml
	[byte[]]$byteArray = [System.Text.Encoding]::ASCII.GetBytes($strUploadData)
	# "To the cloud !"
	try{
		$UploadData = $webclient.UploadData($URI, "PUT", $bytearray)
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
	Get-CIOrgRights -OrgName "PigeonNuggets"

	Returns XML rights for the Org "PigeonNuggets"

	.NOTES
	  NAME: Get-CIOrgRightsXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11
	  KEYWORDS: vmware get vcloud director 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName
	)
	# Retireve the Org object for the Organisation
	$Org = Search-Cloud -QueryType Organization -Filter "Name==$($OrgName)" | Get-CIView
	
	# Make the API call to get the Rights assigned
	[string] $URI = ($Org.Href + "/rights")
	[xml]$xmlOrgRights = Get-vCloudAPIResponse -URI $URI -SessionKey $Org.Client.SessionKey -ContentType "application/vnd.vmware.admin.org.rights+xml;version=27.0"	

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
	
	.PARAMETER RightReference
	The vCloud URI Reference for the new right
	
	.PARAMETER Name
	The name of the Right

	.EXAMPLE
	Add-CIOrgRightXML -RightsXML $xmlReference -RightReference "https://192.168.88.25/api/admin/right/f66d8e79-b584-3d79-a501-d71aaa2ebbf9" -Name "Organization vDC: View"

	.NOTES
	  NAME: Add-vCloudOrgRightXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11
	  KEYWORDS: vmware get vcloud director 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [xml] $RightsXML,
		[Parameter(Mandatory=$True)] [string] $RightReference,
		[Parameter(Mandatory=$True)] [string] $Name
	)
	# First check if the right already exists
	
	if ($RightReference -in $RightsXML.OrgRights.RightReference.Href){
		Write-Warning "The right $($Name) is already assigned for this orgnaisation; no changes will be made."
		$RightsXML
	} else {
		
		# Load the XML and add the new element into the RightReference section
		[xml]$xmlRightsDoc = New-Object system.Xml.XmlDocument
		$xmlRightsDoc.LoadXml($RightsXML.OuterXml)
		
		$newRoleRight = $xmlRightsDoc.CreateElement("RightReference")
		$newRoleRight.SetAttribute("href",$RightReference)
		$newRoleRight.SetAttribute("name",$Name)
		$newRoleRight.SetAttribute("type","application/vnd.vmware.admin.right+xml")
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
	Returns XML of the Global rights for the connected Cloud Infrastructure

	.NOTES
	  NAME: Get-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11
	  KEYWORDS: vmware get vcloud director 
	  #Requires -Version 2.0
	#>
	[string] $vCloudURI = $global:DefaultCIServers.ServiceUri.AbsoluteURI + "admin"
	# Get a CIView for making the call; lazy coding should be fixed later quick handler for the session key
	$SessionObj = (Get-CIUser)[0] | Get-CIView
	(Get-vCloudAPIResponse -URI $vCloudURI -SessionKey $SessionObj.Client.SessionKey -ContentType "application/vnd.vmware.admin.vcloud+xml;version=27.0").VCloud.RightReferences.RightReference
}

function Get-CIOrgRights(){
	<#
	.SYNOPSIS
	Returns a collection of the avaialble rights in the cloud and if they are enabled for the provided Org

	.DESCRIPTION
	Returns the Org rights in vCloud including any rights to vCloud Director Tenant Portal, and also from a new vCloud Director API for NSX which are not exposed through the GUI
	The collection returned will include all rights available with a property "Enabled"; if they are available to the Org this property will be true

	.PARAMETER OrgName
	The Name of the vCloud Organisation

	.EXAMPLE
	Get-CIOrgRights -OrgName "PigeonNuggets"

	Returns a collection of rights for the Org "PigeonNuggets" and if they are enabled

	.NOTES
	  NAME: Get-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11
	  KEYWORDS: vmware get vcloud director 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName
	)
	# Make the API call to get the Rights assigned
	[xml]$xmlOrgRights = Get-CIOrgRightsXML $OrgName

	# Next we need to make a call to the API to resolve the Rights that are avaialble for the Cloud
	$cloudRights = Get-CIRights
	
	# Now build a collection of the rights available vs the rights enabled for the 
	$colRights = New-Object -TypeName System.Collections.ArrayList
	foreach($objRight in $cloudRights){
		$objRightAssignment = New-Object System.Management.Automation.PSObject
		$objRightAssignment | Add-Member Note* RightReference $objRight.href
		$objRightAssignment | Add-Member Note* Name $objRight.name
		$objRightAssignment | Add-Member Note* Enabled ($objRight.href -in $xmlOrgRights.OrgRights.RightReference.Href)	
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
	The Name of the vCloud Organisation
	
	.PARAMETER OutputFilePath
	A fully qualified path to for the file to output the generated CSV

	.EXAMPLE
	Export-CIOrgRights -OrgName "PigeonNuggets" -OutputFilePath "C:\_admin\Output.csv"

	Will write a CSV to C:\_admin\Output.csv containing a list of rights and for the vCloud tenancy and if they are enabled or not

	.NOTES
	  NAME: Export-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName,
		[Parameter(Mandatory=$True)] [string] $OutputFilePath
	)
	$colRights = Get-CIOrgRights -OrgName $OrgName | Select name,enabled | Export-CSV $OutputFilePath -NoTypeInformation
}

function Import-CIOrgRights(){
	<#
	.SYNOPSIS
	Imports a set of vCloud Director Rights from a provided CSV

	.DESCRIPTION
	Will replace the Org rights enabled on a vCloud Organisation with those from a CSV containing the roles in the format name,enabled (role name, true/false)

	.PARAMETER OrgName
	The Name of the vCloud Organisation
	
	.PARAMETER InputCSVFile
	A fully qualified path to for the input CSV file which will be applied to the Organisation

	.EXAMPLE
	Import-CIOrgRights -OrgName "PigeonNuggets" -InputCSVFile "C:\Temp\Rules.csv"

	Will overwrite the OrgRights assigned to the Org PigeonNuggets with the ones defined as enabled in the CSV "C:\Temp\Rules.csv"

	.NOTES
	  NAME: Import-CIOrgRights
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11 
	  #Requires -Version 2.0
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $OrgName,
		[Parameter(Mandatory=$True)] [string] $InputCSVFile
	)
	# Import the rules from the CSV and get a list of valid rights for the Org
	$colRightsCSV = Import-CSV -Path $InputCSVFile
	[xml] $xmlOrgRights = Get-CIOrgRightsXML $OrgName
	$colOrgRights = Get-CIOrgRights $OrgName
	$colEnabledRights = $colRightsCSV | ?{$_.enabled.ToLower() -eq "true"}
	
	
	# First clean the existing configuration of all OrgRights
	[xml]$xmlRightsDoc = New-Object system.Xml.XmlDocument
	$xmlRightsDoc.LoadXml($xmlOrgRights.OuterXml)
	foreach($OrgRight in $xmlRightsDoc.OrgRights.RightReference){
		$xmlRightsDoc.OrgRights.RemoveChild($OrgRight) > $nul
	}
	# Get the rights for the current vCloud instance
	$cloudRights = Get-CIRights
	$newOrgRights = $cloudRights | ?{$_.name -in $colEnabledRights.name}
	# Add the rights from the CSV into the configuration file stripped of the existing rights
	foreach($appliedRight in $newOrgRights){
		$xmlRightsDoc = Add-CIOrgRightXML -RightsXML $xmlRightsDoc -RightReference $appliedRight.href -Name $appliedRight.Name
	}
	
	# Make the API call to PSOT the Rights assigned
	# TO DO: Add confiramtion and error checking
	$Org = Search-Cloud -QueryType Organization -Filter "Name==$($OrgName)" | Get-CIView
	[string] $URI = ($Org.Href + "/rights")
	Publish-vCloudAPICall -URI $URI -SessionKey $Org.Client.SessionKey -ContentType "application/vnd.vmware.admin.org.rights+xml;version=27.0"	-Data $xmlRightsDoc
}

function Remove-CIOrgRight(){
	<#
	.SYNOPSIS
	Removes a single vCloud Director right from an Organisation

	.DESCRIPTION
	Removes a single vCloud Director right from an Organisation

	.PARAMETER OrgName
	The Name of the vCloud Organisation
	
	.PARAMETER Right
	The name of the vCloud Director right to remove from the Organisation

	.EXAMPLE
	Remove-CIOrgRight -OrgName "PigeonNuggets" -Right "vApp Template / Media: Edit"

	Removes the right "vApp Template / Media: Edit" to the Organisation PigeonNuggets if it is enabled

	.NOTES
	  NAME: Remove-CIOrgRight
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11 
	  #Requires -Version 2.0
	#>

	## To be written over the next week :) I am off to the football today
}

function Add-CIOrgRight(){
	<#
	.SYNOPSIS
	Adds a single vCloud Director right to an Organisation

	.DESCRIPTION
	Adds the provided vCloud Director right to the specfied Organisation 

	.PARAMETER OrgName
	The Name of the vCloud Organisation
	
	.PARAMETER Right
	The name of the vCloud Director right to assign

	.EXAMPLE
	Add-CIOrgRight -OrgName "PigeonNuggets" -Right "vApp Template / Media: Edit"

	Adds the right "vApp Template / Media: Edit" to the Organisation PigeonNuggets if not already enabled

	.NOTES
	  NAME: Add-CIOrgRight
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-05-11 
	  #Requires -Version 2.0
	#>
	
	## To be written over the next week :) I am off to the football today

} 	  
#endregion
