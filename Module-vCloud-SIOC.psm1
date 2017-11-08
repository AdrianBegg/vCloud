##########################################################################################
# Name: Module-vCloud-SIOC.psm1
# Date: 08/11/2017 (v0.1)
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
#
# Purpose: PowerShell modules to extend the PowerCLI for vCloud to expose
# additional methods for management SIOC which are currently not exposed
# via the vCloud GUI/PowerCLI cmdlets
#
# Ref: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf
##########################################################################################
# Change Log
# v0.1 - 08/11/2017 - Created module for Org VDC Storage Profile Management and tested on
# vCloud Director for Service Providers 9.0
##########################################################################################
# Known Issues
# 1. When the Default Storage policy for a Org VDC is disabled the Get-OrgVDC cmdlet throws
# an exception (this is used by Get-OrgVdcStorageProfile); at this stage just needs to be
# enabled via the GUI
##########################################################################################

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
	  LASTEDIT: 2017-09-16
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
	  LASTEDIT: 2017-11-08
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
	  LASTEDIT: 2017-11-08
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
	$webclient.Headers.Add("Accept","application/*+xml;version=27.0")
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

#region: OrgVdc
function Get-OrgVdcStorageProfileXML(){
	<#
	.SYNOPSIS
	Returns the OrgVDC Storage Profile configuration as XML from the API call

	.DESCRIPTION
	Returns the OrgVDC Storage Profile configuration as XML from the API call

	.PARAMETER Id
	The vCloud Object Id for the Org VDC to query

	.EXAMPLE
	Get-OrgVdcAccessRightsXML -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8"

	Returns the AccessControl details in XML format for the Org VDC with the Id urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8

	.NOTES
	  NAME: Get-OrgVdcStorageProfileXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-11-8
	  REFERENCE: http://pubs.vmware.com/vcd-820/index.jsp?topic=%2Fcom.vmware.vcloud.api.sp.doc_27_0%2FGUID-D261BF1D-25D3-46EA-84CF-6ABAA45267F0.html
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $Id
	)
	try{
		$objOrgVDCStorageView = Get-CIView -Id $Id
	} catch {
		throw "An error occured quering the Org VDC Storage Profile with the ID $OrgVDCStorageProfileId"
	}
	[string] $URI = $objOrgVDCStorageView.Href
	[xml]$XMLOrgVDCStorageProfile = (Get-vCloudAPIResponse -URI $URI -ContentType $objOrgVDCStorageView.Type)
	# Return to the caller
	$XMLOrgVDCStorageProfile
}

function Set-OrgVdcStorageProfileSIOCXML(){
	<#
	.SYNOPSIS
	Generates a correctly formed Org VDC Storage Profile XML document for POST to the REST API for vCloud Director with the specified SIOC settings.

	.DESCRIPTION
	This cmdlet generates an Org VDC Storage Profile configuration document for the provided OrgVDC Storage Profile with the SIOC settings set as required. This can then be sent as a POST to vCloud Director to modify the SIOC settings.

	.PARAMETER OrgVDCStorageProfileId
    The vCloud Object Id for the Org VDC Storge Profile/Policy you wish to target

	.PARAMETER SIOCEnabled
	Enables/Disables SIOC on the Org VDC Storage Profile. If being enabled for the first time DiskIOPSMax, DiskIopsDefault and DiskIOPsPerGB must be provided.

	.PARAMETER DiskIopsMax
	The maximum IOPs value that this storage profile is permitted to deliver. Value must be in the range 200-4000, and cannot be less than the value of DiskIopsDefault. Value of 0 means this max setting is is disabled and there is no max disk IOPS restriction.

	.PARAMETER DiskIopsDefault
	This value is applied when provisioning a disk that does not specify vcloud:iops. Value must be in the range 200-4000, and cannot be greater than the value of DiskIopsMax. If DiskIopsPerGbMax is greater than 0 and if (diskSize * DiskIopsPerGbMax) less than DiskIopsDefault, then the default iops for the disk will be set as (diskSize * DiskIopsPerGbMax).

	.PARAMETER DiskIopsPerGbMax
	The maximum disk IOPs per GB value that this storage profile is permitted to deliver. A value of 0 means there is no perGB IOPS restriction.

	.EXAMPLE
	Set-OrgVdcStorageProfileSIOCXML -Id "urn:vcloud:vdcstorageProfile:a2925d02-a4be-4d0a-9003-cbb050ed0e7f" -SIOCEnabled $true -DiskIopsMax 1000 -DiskIopsDefault 100 -DiskIopsPerGbMax 100
	Will return an XML configuration document with the Storage IO Control configured on the Org VDC Storage Profile with the ID "urn:vcloud:vdcstorageProfile:a2925d02-a4be-4d0a-9003-cbb050ed0e7f" with a Max IOPS of 1000 IOPs, Default IOPS of 100 and a Disk IOPS Per GB of 100

	.NOTES
	  NAME: Set-OrgVdcStorageProfileSIOCXML
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-11-08
	  REFERENCE http://pubs.vmware.com/vcd-810/index.jsp?topic=%2Fcom.vmware.vcloud.api.reference.doc_20_0%2Fdiff%2Ftypes%2FVdcStorageProfileIopsSettingsType.html
	#>
	Param(
		[Parameter(Mandatory=$True)]
			[ValidateNotNullorEmpty()] [string] $OrgVDCStorageProfileId,
		[Parameter(Mandatory=$True)]
			[ValidateNotNullOrEmpty()] [bool] $SIOCEnabled,
		[Parameter(Mandatory=$True)]
			[ValidateRange(0,1000000000)] [int] $DiskIopsMax,
		[Parameter(Mandatory=$True)]
			[ValidateRange(0,1000000000)] [int] $DiskIopsDefault,
		[Parameter(Mandatory=$True)]
			[ValidateRange(0,1000000000)] [int] $StorageProfileIopsLimit,
		[Parameter(Mandatory=$True)]
			[ValidateRange(0,1000000000)] [int] $DiskIopsPerGbMax
	)
	# Return the current XML document that represents the Organisational VDC Storage Profile
	[xml] $XMLOrgVDCSPConfig = Get-OrgVdcStorageProfileXML -Id $OrgVDCStorageProfileId

	# First check if the section required exists and create the nodes if required
	if($XMLOrgVDCSPConfig.AdminVdcStorageProfile.IopsSettings -eq $null){

		# Create an XML Node formed correctly for the API call
		[Xml.XmlNode] $xmlIopsSettingNode = $XMLOrgVDCSPConfig.CreateNode("element","IopsSettings","")

		# Add the Setting for the node to enable SIOC
		[Xml.XmlNode] $xmlSIOCEnabled = $XMLOrgVDCSPConfig.CreateNode("element","Enabled","");
		$xmlSIOCEnabled.InnerText = $SIOCEnabled.ToString().ToLower()
		$xmlIopsSettingNode.AppendChild($xmlSIOCEnabled) > $nul

		# Add the Setting for the node to the tree for DiskIopsMax
		[Xml.XmlNode] $xmlDiskIopsMax = $XMLOrgVDCSPConfig.CreateNode("element","DiskIopsMax","");
		$xmlDiskIopsMax.InnerText = $DiskIopsMax
		$xmlIopsSettingNode.AppendChild($xmlDiskIopsMax) > $nul

		# Add the Setting for the node to the tree for DiskIopsDefault
		[Xml.XmlNode] $xmlDiskIopsDefault = $XMLOrgVDCSPConfig.CreateNode("element","DiskIopsDefault","");
		$xmlDiskIopsDefault.InnerText = $DiskIopsDefault
		$xmlIopsSettingNode.AppendChild($xmlDiskIopsDefault) > $nul

		# Add the Setting for the node to the tree for Storage Profile Iops Limit (The Provider VDC Limit
		[Xml.XmlNode] $xmlStorageProfileIopsLimit = $XMLOrgVDCSPConfig.CreateNode("element","StorageProfileIopsLimit","");
		$xmlStorageProfileIopsLimit.InnerText = $StorageProfileIopsLimit
		$xmlIopsSettingNode.AppendChild($xmlStorageProfileIopsLimit) > $nul

		# Add the Setting for the node to the tree for Storage Profile Iops Limit (The Provider VDC Limit
		[Xml.XmlNode] $xmlDiskIopsPerGbMax = $XMLOrgVDCSPConfig.CreateNode("element","DiskIopsPerGbMax","");
		$xmlDiskIopsPerGbMax.InnerText = $DiskIopsPerGbMax
		$xmlIopsSettingNode.AppendChild($xmlDiskIopsPerGbMax) > $nul

		# Create a new XML Node for SIOC; the Node needs to be ordered immediately after the Default Element to be considered valid
		$xmlIsDefaultNode = $XMLOrgVDCSPConfig.AdminVdcStorageProfile.GetElementsByTagName("Default")[0]
		$XMLOrgVDCSPConfig.AdminVdcStorageProfile.InsertAfter($xmlIopsSettingNode,$xmlIsDefaultNode) > $nul
	} else {
		# Update the values based on the provided values
		$XMLOrgVDCSPConfig.AdminVdcStorageProfile.IopsSettings.Enabled = ($SIOCEnabled.ToString()).ToLower()
		$XMLOrgVDCSPConfig.AdminVdcStorageProfile.IopsSettings.DiskIopsMax = $DiskIopsMax.ToString()
		$XMLOrgVDCSPConfig.AdminVdcStorageProfile.IopsSettings.DiskIopsDefault = $DiskIopsDefault.ToString()
		$XMLOrgVDCSPConfig.AdminVdcStorageProfile.IopsSettings.StorageProfileIopsLimit = $StorageProfileIopsLimit.ToString()
		$XMLOrgVDCSPConfig.AdminVdcStorageProfile.IopsSettings.DiskIopsPerGbMax = $DiskIopsPerGbMax.ToString()
	}
	# Get rid of the unwanted namespace element added by .NET and return to the caller
	$XMLOrgVDCSPConfig = [xml] $XMLOrgVDCSPConfig.OuterXml.Replace(" xmlns=`"`"", "")

	# Return the XML to the caller
	$XMLOrgVDCSPConfig
}

function Get-OrgVdcStorageProfile(){
	<#
	.SYNOPSIS
	Returns the Storage Policies/Profiles which are defined on the target Organisation Virtual Datacenter object.

	.DESCRIPTION
	Returns a collection of Storage Policies/Profiles which are defined on the target Organisation Virtual Datacenter object.

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OrgVDC
	The name of the Organization Virtual Datacenter to query

	.PARAMETER OrgVDCId
	The vCloud Object Id for the Org VDC to query

	.PARAMETER StorageProfileId
	The vCloud Object Id for the Org VDC Storage Profile/Policy you wish to target

	.EXAMPLE
	Get-OrgVdcStorageProfile -OrgName "*"

	Returns a collection of all Storage Policies which are accessible in the currently logged in users scope.

	.EXAMPLE
	Get-OrgVdcStorageProfile -OrgName "PigeonNuggets"

	Returns a collection of all Storage Policies defined on all Org VDC's in the Organisation "PigeonNuggets"

	.EXAMPLE
	Get-OrgVdcStorageProfile -OrgName "PigeonNuggets" -OrgVDC "Production"

	Returns the Storage Policies defined on the the Org VDC "Production" in the Organisation "PigeonNuggets"

 	.EXAMPLE
	Get-OrgVdcStorageProfile -OrgVDCId "urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8"

	Returns the Storage Policies defined on the the Org VDC with the vCloud Object Id urn:vcloud:vdc:0a91d569-7653-40ed-8258-c90f12ec05c8

	.EXAMPLE
	Get-OrgVdcStorageProfile -Id "urn:vcloud:vdcstorageProfile:0a6b3ef2-00e6-43ae-889c-4922a39db21f"

	Returns the object for the Org VDC Storage Profile with the vCloud Object Id "urn:vcloud:vdcstorageProfile:0a6b3ef2-00e6-43ae-889c-4922a39db21f"

	.NOTES
	  NAME: Get-OrgVdcStorageProfile
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-24
	  REFERENCE: http://pubs.vmware.com/vcd-820/topic/com.vmware.ICbase/PDF/vcloud_sp_api_guide_27_0.pdf p.194
	#>
	[CmdletBinding(DefaultParameterSetName="ByName")]
	Param(
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgName = "*",
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgVDC,
		[Parameter(Mandatory=$True,ParameterSetName = "ByOrgId")]
			[ValidateNotNullorEmpty()] [string] $OrgVDCId,
		[Parameter(Mandatory=$True,ParameterSetName = "StorageProfileId")]
			[ValidateNotNullorEmpty()] [string] $Id
	)
	# Test to see if vCloud is connected
	if(!(Test-vCloudEnvironment)){
		Break
	}
	# Check which Parameter Set has been defined and retreive the objects for the query
	$colStorageProfileViews = New-Object -TypeName System.Collections.ArrayList
	if($PSCmdlet.ParameterSetName -in ("ByName","ByOrgId")){
		if($PSCmdlet.ParameterSetName -eq "ByName"){
			if(!([string]::IsNullOrEmpty($OrgVDC))){
				$colOrgVDC = (Get-OrgVdc -Name $OrgVDC -Org $OrgName)
			} else {
				$colOrgVDC = (Get-OrgVdc -Org $OrgName)
			}
		} else {
			$colOrgVDC = (Get-OrgVDC -Id $OrgVDCId)
		}
		# Query the Org VDCs and obtain the Storage Profile References assigned into a collection
		foreach($objOrgVDC in $colOrgVDC){
			# Get a collection of VdcStorageProfiles API URIs from the OrgVDC specification
			$colStorageProfileRef = (Get-CIView -Id $objOrgVDC.Id -ViewLevel User).VdcStorageProfiles.VdcStorageProfile
			foreach($StorageProfileSpec in $colStorageProfileRef){
				# Call the API to get the Id of the object to pass to Get-CIView for consistent processing
				try{
					[xml]$XMLStorageProfileResponse = (Get-vCloudAPIResponse -URI $StorageProfileSpec.Href -ContentType $StorageProfileSpec.Type)
				} catch {
					throw "An error occured attempting to query the Storage Profile with the URI $($StorageProfileSpec.Href)"
				}
				# Create an object with the properties for further processing
				$objStorageProfileView = New-Object System.Management.Automation.PSObject
				$objStorageProfileView | Add-Member Note* Id $XMLStorageProfileResponse.VdcStorageProfile.Id
				$objStorageProfileView | Add-Member Note* StorageProfileView (Get-CIView -Id $XMLStorageProfileResponse.VdcStorageProfile.Id)
                $objStorageProfileView | Add-Member Note* OrgVDC $objOrgVDC
				$objStorageProfileView | Add-Member Note* StorageMBUsed $XMLStorageProfileResponse.VdcStorageProfile.StorageUsedMB
				# Add the IOPS Settings from the API call (not all settings are exposed through the views)
				if($XMLStorageProfileResponse.VdcStorageProfile.IopsSettings -ne $null){
					$objIOPSSettings = New-Object System.Management.Automation.PSObject
					$objIOPSSettings | Add-Member Note* Enabled $XMLStorageProfileResponse.VdcStorageProfile.IopsSettings.Enabled
					$objIOPSSettings | Add-Member Note* DiskIopsMax $XMLStorageProfileResponse.VdcStorageProfile.IopsSettings.DiskIopsMax
					$objIOPSSettings | Add-Member Note* DiskIopsDefault $XMLStorageProfileResponse.VdcStorageProfile.IopsSettings.DiskIopsDefault
					$objIOPSSettings | Add-Member Note* StorageProfileIopsLimit $XMLStorageProfileResponse.VdcStorageProfile.IopsSettings.StorageProfileIopsLimit
					$objIOPSSettings | Add-Member Note* DiskIopsPerGbMax $XMLStorageProfileResponse.VdcStorageProfile.IopsSettings.DiskIopsPerGbMax
					$objStorageProfileView | Add-Member Note* IopsSettings $objIOPSSettings
				} else {
					$objStorageProfileView | Add-Member Note* IopsSettings $null
				}
				$colStorageProfileViews.Add($objStorageProfileView) > $nul
			}
		}
	} elseif($PSCmdlet.ParameterSetName -eq "StorageProfileId"){
		try{
			# Get the Storage Profile View
			$objStoragePolicy = Get-CIView -Id $Id -ViewLevel Admin
		} catch {
			throw "A Storage Policy with the Id $Id could not be found. Please check the values and try again."
		}
		try {
			# Get the OrgVDC that owns the object
			[xml]$XMLStorageProfileResponse = (Get-vCloudAPIResponse -URI $objStoragePolicy.Href -ContentType $objStoragePolicy.Type)
			$OrgVDCURI = ($XMLStorageProfileResponse.AdminVdcStorageProfile.Link | ?{$_.rel -eq "up"}).href
			$OrgVDCType =  ($XMLStorageProfileResponse.AdminVdcStorageProfile.Link | ?{$_.rel -eq "up"}).type
			[xml]$XMLOrgVDCResponse = (Get-vCloudAPIResponse -URI $OrgVDCURI -ContentType $OrgVDCType)
			$objOrgVDC = (Get-OrgVDC -Id $XMLOrgVDCResponse.AdminVdc.Id)
		} catch {
			throw "An error occured resolving the OrgVDC that owns the Storage Policy with the Id $StorageProfileId"
		}
		# Create an object with the properties for further processing
		$objStorageProfileView = New-Object System.Management.Automation.PSObject
		$objStorageProfileView | Add-Member Note* Id $StorageProfileId
		$objStorageProfileView | Add-Member Note* StorageProfileView $objStoragePolicy
        $objStorageProfileView | Add-Member Note* OrgVDC $objOrgVDC
		$objStorageProfileView | Add-Member Note* StorageMBUsed $XMLStorageProfileResponse.AdminVdcStorageProfile.StorageUsedMB
		# Add the IOPS Settings from the API call (not all settings are exposed through the views)
		if($XMLStorageProfileResponse.AdminVdcStorageProfile.IopsSettings -ne $null){
			$objIOPSSettings = New-Object System.Management.Automation.PSObject
			$objIOPSSettings | Add-Member Note* Enabled $XMLStorageProfileResponse.AdminVdcStorageProfile.IopsSettings.Enabled
			$objIOPSSettings | Add-Member Note* DiskIopsMax $XMLStorageProfileResponse.AdminVdcStorageProfile.IopsSettings.DiskIopsMax
			$objIOPSSettings | Add-Member Note* DiskIopsDefault $XMLStorageProfileResponse.AdminVdcStorageProfile.IopsSettings.DiskIopsDefault
			$objIOPSSettings | Add-Member Note* StorageProfileIopsLimit $XMLStorageProfileResponse.AdminVdcStorageProfile.IopsSettings.StorageProfileIopsLimit
			$objIOPSSettings | Add-Member Note* DiskIopsPerGbMax $XMLStorageProfileResponse.AdminVdcStorageProfile.IopsSettings.DiskIopsPerGbMax
			$objStorageProfileView | Add-Member Note* IopsSettings $objIOPSSettings
		} else {
			$objStorageProfileView | Add-Member Note* IopsSettings $null
		}
		$colStorageProfileViews.Add($objStorageProfileView) > $nul
	}
	# Now we have a collection of Org VDC Storage Policies that we can build further properties for
	# Create a collection to store the results
	$colStorageProfile = New-Object -TypeName System.Collections.ArrayList
	foreach($objStorageProfileView in $colStorageProfileViews){
		# Set the Storage View object
		$objStorageView = $objStorageProfileView.StorageProfileView

		# Create the object
		$objOrgVDCStorageProfile = New-Object System.Management.Automation.PSObject
		$objOrgVDCStorageProfile | Add-Member Note* Id $objStorageView.Id
		$objOrgVDCStorageProfile | Add-Member Note* Name $objStorageView.Name
		$objOrgVDCStorageProfile | Add-Member Note* Description $objStorageView.Description
		$objOrgVDCStorageProfile | Add-Member Note* Enabled $objStorageView.Enabled
		$objOrgVDCStorageProfile | Add-Member Note* Default $objStorageView.Default
		$objOrgVDCStorageProfile | Add-Member Note* Limit $objStorageView.Limit
		$objOrgVDCStorageProfile | Add-Member Note* Units $objStorageView.Units
        $objOrgVDCStorageProfile | Add-Member Note* StorageMBUsed $objStorageProfileView.StorageMBUsed
        $objOrgVDCStorageProfile | Add-Member Note* IopsSettings $objStorageProfileView.IopsSettings
		$objOrgVDCStorageProfile | Add-Member Note* OrgVDC $objStorageProfileView.OrgVDC

		# Need to check if this is a valid value or returned at all
		if($objStorageView.ProviderVdcStorageProfile -ne $null){
			# Finally resovle the Provider VDC Storage Profile
			[xml]$XMLProviderVDCStorageProfile = (Get-vCloudAPIResponse -URI $objStorageView.ProviderVdcStorageProfile.Href -ContentType $objStorageView.ProviderVdcStorageProfile.Type)

			# Check if the user is logged into the System Org
			if($global:DefaultCIServers.Org -eq "System"){
				$objProviderVdcStorageProfile = Get-ProviderVdcStorageProfile -Id $XMLProviderVDCStorageProfile.ProviderVdcStorageProfile.id
				$objOrgVDCStorageProfile | Add-Member Note* ProviderVDCStorageProfile $objProviderVdcStorageProfile
			}
		}
		$colStorageProfile.Add($objOrgVDCStorageProfile) > $null
	}
	# Return the collection to the caller
	$colStorageProfile
}

function Set-OrgVdcStorageProfile(){
	<#
	.SYNOPSIS
	Sets the properties of a provided Org VDC Storage Policies/Profiles.

	.DESCRIPTION
	This cmdlet can be used to amend the properties of a Storage Policies/Profiles object. This cmdlet allows the object to be set as default or adjust the storage quotas

	.PARAMETER OrgName
	The Name of the vCloud Organisation.

	.PARAMETER OrgVDC
	The name of the Organization Virtual Datacenter to query

	.PARAMETER StorageProfileName
	The Name of the Storage Policy

	.PARAMETER Id
    The vCloud Object Id for the Org VDC Storge Profile/Policy you wish to target

    .PARAMETER StorageProfileObject
    A collection of Storage Profile Object returned by the Get-OrgVdcStorageProfile

    .PARAMETER Default
    If set to True will mark the Storage Profile as the default for the Organisation; NOTE: This can not be set to false; this switch is used to set a storage policy as the default only

    .PARAMETER Enabled
    If set to True will mark the Storage Profile as the Enabled for the Organisation for use; if it is set to False this will disable the object in vCloud

    .PARAMETER Description
    Updates the Description of the Storage Profile/Policy

    .PARAMETER Limit
    Updates the Storage Limit (in MB) for the Storage Profile/Policy. For Unlimmited set to 0

	.PARAMETER SIOCEnabled
	Enables/Disables SIOC on the Org VDC Storage Profile. If being enabled for the first time DiskIOPSMax, DiskIopsDefault and DiskIOPsPerGB must be provided.

	.PARAMETER DiskIopsMax
	The maximum IOPs value that this storage profile is permitted to deliver. Value must be in the range 200-4000, and cannot be less than the value of DiskIopsDefault. Value of 0 means this max setting is is disabled and there is no max disk IOPS restriction.

	.PARAMETER DiskIopsDefault
	This value is applied when provisioning a disk that does not specify vcloud:iops. Value must be in the range 200-4000, and cannot be greater than the value of DiskIopsMax. If DiskIopsPerGbMax is greater than 0 and if (diskSize * DiskIopsPerGbMax) less than DiskIopsDefault, then the default iops for the disk will be set as (diskSize * DiskIopsPerGbMax).

	.PARAMETER DiskIopsPerGbMax
	The maximum disk IOPs per GB value that this storage profile is permitted to deliver. A value of 0 means there is no perGB IOPS restriction.

    .EXAMPLE
	Get-OrgVdcStorageProfile -Id "urn:vcloud:vdcstorageProfile:a2925d02-a4be-4d0a-9003-cbb050ed0e7f" -Default $true

    Will set the Org VDC Storage Profile with the vCloud Object Id "urn:vcloud:vdcstorageProfile:a2925d02-a4be-4d0a-9003-cbb050ed0e7f" as the default

	.EXAMPLE
	Set-OrgVdcStorageProfile -OrgName "PigeonNuggets" -Limit 2048

	Will amend the Storage Quota for all Storage Profiles defined in the Organisation "PigeonNuggets" to 2048MB (if possible)

    .EXAMPLE
	Get-OrgVdcStorageProfile -OrgName "PigeonNuggets" -OrgVDC "Production" | Set-OrgVdcStorageProfile -Limit 2048

	Will amend the Storage Quota for all Storage Profiles defined in the Organisation "PigeonNuggets" and Org VDC  "Production" to 2048MB (if possible)

    .EXAMPLE
    Set-OrgVdcStorageProfile -OrgName "PigeonNuggets" -OrgVDC "Production" -StorageProfileName "Tier 1" -Enabled $false

    Will disable the Storage Profiles defined in the Organisation "PigeonNuggets" and Org VDC "Production" named "Tier 1"

    .EXAMPLE
    Set-OrgVdcStorageProfile -OrgName "PigeonNuggets" -StorageProfileName "Tier 1" -Enabled $false -Description "This storage profile is no longer used; please use Gold instead"
	Will disable the Storage Profiles defined in the Organisation "PigeonNuggets" with the name of "Tier 1" add a description "This storage profile is no longer used; please use Gold instead"

	.EXAMPLE
	Set-OrgVdcStorageProfile -Id "urn:vcloud:vdcstorageProfile:a2925d02-a4be-4d0a-9003-cbb050ed0e7f" -SIOCEnabled $true -DiskIopsMax 1000 -DiskIopsDefault 100 -DiskIopsPerGbMax 100
	Will enable Storage IO Control on the Org VDC Storage Profile with the ID "urn:vcloud:vdcstorageProfile:a2925d02-a4be-4d0a-9003-cbb050ed0e7f" with a Max IOPS of 1000 IOPs, Default IOPS of 100 and a Disk IOPS Per GB of 100

	.EXAMPLE
	Set-OrgVdcStorageProfile -OrgName "PigeonNuggets" -StorageProfileName "Tier 1" -SIOCEnabled $false
	Will disable Storage IO Control on the Org VDC Storage Profile  Tier 1 in the Org PigeonNuggets.

	.NOTES
	  NAME: Set-OrgVdcStorageProfile
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-11-08
      REFERENCES: http://pubs.vmware.com/vcd-820/index.jsp?topic=%2Fcom.vmware.vcloud.api.sp.doc_27_0%2FGUID-D261BF1D-25D3-46EA-84CF-6ABAA45267F0.html, http://pubs.vmware.com/vcd-810/index.jsp?topic=%2Fcom.vmware.vcloud.api.reference.doc_20_0%2Fdiff%2Ftypes%2FVdcStorageProfileIopsSettingsType.html
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgName,
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $OrgVDC,
        [Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $StorageProfileName,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
            [ValidateNotNullorEmpty()] [string] $Id,
        [Parameter(Mandatory=$True,ParameterSetName = "ByStorageObject", ValueFromPipeline=$True)]
            [ValidateNotNullorEmpty()] [PSObject[]] $StorageProfileObject,
        [Parameter(Mandatory=$False)]
            [ValidateScript({
				if($_ -ne $true){
					throw "This parameter can only be set to True. In order to unset an OrgVdcStorageProfile as the default simply set another as the default."
				} else {
					$true
				}})] [bool] $Default,
        [Parameter(Mandatory=$False)]
          [ValidateNotNull()] [bool] $Enabled,
        [Parameter(Mandatory=$False)]
            [ValidateNotNullorEmpty()] [string] $Description,
        [Parameter(Mandatory=$False)]
			[ValidateRange(0,10000000000)] [int] $Limit,
		[Parameter(Mandatory=$False)]
			[ValidateNotNullOrEmpty()] [bool] $SIOCEnabled,
		[Parameter(Mandatory=$False)]
			[ValidateRange(0,1000000000)] [int] $DiskIopsMax,
		[Parameter(Mandatory=$False)]
			[ValidateRange(0,1000000000)] [int] $DiskIopsDefault,
		[Parameter(Mandatory=$False)]
			[ValidateRange(0,1000000000)] [int] $DiskIopsPerGbMax
	)
	Process{
		# Check if the server is connected and version is greater then 8.10
		if(!(Test-vCloudEnvironment -Version 8.10)){
			Break
		}
		# Get the Storage Profile objects to operate on
		if($PSCmdlet.ParameterSetName -eq "ById"){
			$colStorageProfiles = Get-OrgVdcStorageProfile -Id $Id
		} elseif($PSCmdlet.ParameterSetName -eq "ByStorageObject"){
			$colStorageProfiles = $StorageProfileObject
		} elseif($PSCmdlet.ParameterSetName -eq "ByName"){
			if(!([string]::IsNullOrEmpty($OrgVDC))){
				$colStorageProfiles = Get-OrgVdcStorageProfile -OrgName $OrgName -OrgVDC $OrgVDC
			} else {
				$colStorageProfiles = Get-OrgVdcStorageProfile -OrgName $OrgName
			}
			# if the Storage Profile name was provided filter the collection
			if(!([string]::IsNullOrEmpty($StorageProfileName))){
				$colStorageProfiles = $colStorageProfiles | ?{$_.Name -eq $StorageProfileName}
			}
		}
		# Check that objects have been returned by the parameters
		if($colStorageProfiles -eq $null){
			throw "No Org VDC Storage Profiles could be found with the provided values. Please review and try again."
		}
		# Next operate on the objects
		foreach($objStoragePolicy in $colStorageProfiles){
			# Check if any SIOC Settings are to be amended and make decsisions for API based updates
			if(($PSBoundParameters.ContainsKey("SIOCEnabled")) -or ($PSBoundParameters.ContainsKey("DiskIopsMax")) -or ($PSBoundParameters.ContainsKey("DiskIopsDefault")) -or ($PSBoundParameters.ContainsKey("DiskIopsPerGbMax"))){
				# First check if SIOC settings are currently defined
				if($objStoragePolicy.IopsSettings -eq $null){
					# If no settings have been provided previously require the IOPS settings are provided
					if(!($PSBoundParameters.ContainsKey("DiskIopsMax")) -or !($PSBoundParameters.ContainsKey("DiskIopsDefault")) -or !($PSBoundParameters.ContainsKey("DiskIopsPerGbMax"))){
						throw "In order to enable SIOC for the first time on an Org VDC Storage Profile the values for DiskIopsMax, DiskIopsDefault and DiskIopsPerGbMax must be provided."
					}
				}
				# If the IOPS values are being updated that there is sufficent capacity
				if($PSBoundParameters.ContainsKey("DiskIopsMax")){
					[int]$IOPSAvailable = ($objStoragePolicy.ProviderVDCStorageProfile.IopsCapacity - $objStoragePolicy.ProviderVDCStorageProfile.IopsAllocated)
					if($DiskIopsMax -gt $IOPSAvailable){
						throw "The requested Maximum IOPS ($DiskIopsMax) exceeds the IOPS available in the Provided Storage Profile ($IOPSAvailable)"
					}
				} else {
					# If nothing was provided set to the current value set against the profile
					$DiskIopsMax = $objStoragePolicy.IopsSettings.DiskIopsMax
				}
				# Check that the values provided for the Iops Settings are less then the defined Maximum for the Storage Profile
				if($PSBoundParameters.ContainsKey("DiskIopsDefault")){
					if($DiskIopsDefault -gt $DiskIopsMax){
						throw "The requested value for DiskIopsDefault ($DiskIopsDefault) is greater then the maximum available $DiskIopsMax"
					}
				} else {
					$DiskIopsDefault = $objStoragePolicy.IopsSettings.DiskIopsDefault
				}
				if($PSBoundParameters.ContainsKey("DiskIopsPerGbMax")){
					if($DiskIopsPerGbMax -gt $DiskIopsMax){
						throw "The requested value for DiskIopsPerGbMax ($DiskIopsPerGbMax) is greater then the maximum available $DiskIopsMax"
					}
				} else {
					$DiskIopsPerGbMax = $objStoragePolicy.IopsSettings.DiskIopsPerGbMax
				}
				# All SIOC input has been validated now make the update to the SIOC settings via an API call
				$XMLOrgVDCSPConfig = Set-OrgVdcStorageProfileSIOCXML -OrgVDCStorageProfileId $objStoragePolicy.id -SIOCEnabled $SIOCEnabled -StorageProfileIopsLimit $objStoragePolicy.ProviderVDCStorageProfile.IopsCapacity -DiskIopsMax $DiskIopsMax -DiskIopsDefault $DiskIopsDefault -DiskIopsPerGbMax $DiskIopsPerGbMax
				$objStoragePolicyView = Get-CIView -Id $objStoragePolicy.id
				try{
					Publish-vCloudAPICall -URI $objStoragePolicyView.Href -ContentType $objStoragePolicyView.Type -Data $XMLOrgVDCSPConfig
				} catch {
					throw "An error occured updating the Storage IO Control parameters on the Storage Profile $objStoragePolicy.id"
				}
			}
			# Get a Storage Profile View object for other updates
			$objStoragePolicyView = Get-CIView -Id $objStoragePolicy.id
			[bool] $UpdateMade = $false

			# Check if the Storage Profile is to be set as the default and make the change
			if($PSBoundParameters.ContainsKey("Default")){
				if($Default -eq $true){
					if($objStoragePolicy.Default -eq $true){
						Write-Warning "The storage policy is already marked as the default. No changes have been made."
					} else {
						# Make the updates
						$objStoragePolicyView.Default = $true
						$objStoragePolicy.Default = $true
						$UpdateMade = $true
					}
				}
			}
			# Next make changes to if the Storage Policy is enabled or not
			if($PSBoundParameters.ContainsKey("Enabled")){
				if($Enabled -eq $false){
					# First check if the Storage Policy is currently enabled
					if($objStoragePolicy.Enabled -eq $false){
						Write-Warning "The storage policy is currently disabled. No changes have been made."
					} else {
						# Check if the Storage Policy is currently the default and if this is being updated; can not disable a Default Storage Policy
						if($objStoragePolicy.Default -eq $true){
							throw "The storage policy is the default storage policy for a VDC cannot be disabled. Please set a new default storage policy first and try the operation again."
						} else {
							# Make the updates
							$objStoragePolicyView.Enabled = $Enabled
							$UpdateMade = $true
						}
					}
				} elseif($Enabled -eq $true){
					$objStoragePolicyView.Enabled = $Enabled
					$UpdateMade = $true
				}
			}
			# Check if the Description requires update
			if(!([string]::IsNullOrEmpty($Description))){
				$objStoragePolicyView.Description = $Description
				$UpdateMade = $true
			}
			# Check if the Limits on the Storage Profile are changing
			if($PSBoundParameters.ContainsKey("Limit")){
				if($Limit -lt $objStoragePolicy.StorageMBUsed){
					throw "The provided limit for the storage quota of $Limit is less than already used ($($objStoragePolicy.StorageMBUsed))"
				} else {
					$objStoragePolicyView.Limit = $Limit
					$UpdateMade = $true
				}
			}
			if($UpdateMade){
				try{
					$objStoragePolicyView.UpdateServerData() > $null
					# Return the updated objects
				} catch {
					throw "An error occured whilst applying the changes to the requested Storage Profile."
				}
			}
			Get-OrgVdcStorageProfile -Id $objStoragePolicyView.Id
		}
	}
}
#endregion

#region: ProviderVDC
function New-ProviderVdcStorageProfileObject(){
	<#
	.SYNOPSIS
	A private support function which returns a Provider Vdc Storage Profile Object from the API.

	.DESCRIPTION
	This function returns a Provider Vdc Storage Profile Object from API URI provided by the caller.

	.PARAMETER StorageProfileURI
	The API URI provided by Get-CIView call against the object

	.PARAMETER ContentType
	The Content Type of the Object

	.EXAMPLE
	New-ProviderVdcStorageProfileObject -StorageProfileURI "https://vcd.pigeonnuggets.com/api/admin/extension/pvdcStorageProfile/60face83-24fe-4025-8b9b-3194d42ace9b" -ContentType "application/vnd.vmware.admin.vmwPvdcStorageProfile+xml"

	Returns a ProviderVDCStorageProfile object created from the object at the URI https://vcd.pigeonnuggets.com/api/admin/extension/pvdcStorageProfile/60face83-24fe-4025-8b9b-3194d42ace9b

	.NOTES
	  NAME: New-ProviderVdcStorageProfileObject
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-13
	#>
	Param(
		[Parameter(Mandatory=$True)] [string] $StorageProfileURI,
		[Parameter(Mandatory=$True)] [string] $ContentType
	)
	try {
		# Make the API call for the provided link
		[xml]$XMLStorageProfileResponse = (Get-vCloudAPIResponse -URI $StorageProfileURI -ContentType $ContentType)
	} catch {
		throw "An error occured querying the Provider Storage Profile at URI $StorageProfileURI"
	}
	# Next make a call to get the vCenter Storage Profile details if the Tier is enabled
	if($XMLStorageProfileResponse.VMWProviderVdcStorageProfile.VimStorageProfile -ne $null){
		[xml]$XMLVCStorageProfileOwner = (Get-vCloudAPIResponse -URI ($XMLStorageProfileResponse.VMWProviderVdcStorageProfile.VimStorageProfile.VimServerRef.href) -ContentType $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.VimStorageProfile.VimServerRef.type)
		$vCenter = Get-CIView -Id $XMLVCStorageProfileOwner.VimServer.Id
	} else {
		# Catch when a vCenter resource does not exist backing the object
		$vCenter = $null
	}
	# Create the object for the Provider VDC Storage Profile
	$objProviderVDCStorageProfile = New-Object System.Management.Automation.PSObject
	$objProviderVDCStorageProfile | Add-Member Note* Id $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.id
	$objProviderVDCStorageProfile | Add-Member Note* Name $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.Name
	$objProviderVDCStorageProfile | Add-Member Note* Enabled $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.Enabled
	$objProviderVDCStorageProfile | Add-Member Note* CapacityTotal $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.CapacityTotal
	$objProviderVDCStorageProfile | Add-Member Note* CapacityUsed $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.CapacityUsed
	$objProviderVDCStorageProfile | Add-Member Note* Units $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.Units
	$objProviderVDCStorageProfile | Add-Member Note* IopsCapacity $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.IopsCapacity
	$objProviderVDCStorageProfile | Add-Member Note* IopsAllocated $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.IopsAllocated
	$objProviderVDCStorageProfile | Add-Member Note* vCenter $vCenter
	$objProviderVDCStorageProfile | Add-Member Note* vCenterMoRef $XMLStorageProfileResponse.VMWProviderVdcStorageProfile.VimStorageProfile.MoRef

	# Return the object
	$objProviderVDCStorageProfile
}

function Get-ProviderVdcStorageProfile(){
	<#
	.SYNOPSIS
	Returns the Provider VDC Storage Profile objects for the target organisation.

	.DESCRIPTION
	Returns a collection of Provider VDC Storage Policies which are defined on the target Provider Virtual Datacenter object or Id.
	Note: This cmdlet is only available to Provider Administrators.

	.PARAMETER ProviderVdcName
	The Name of the Provider VDC to query. Wildcards can be used for filtering (eg. * or Ad*)

	.PARAMETER ProviderVdcId
	The vCloud Object Id for the Provider VDC to query.

	.PARAMETER Id
	The vCloud Object Id for the Org Provider VDC Storage Profile to query.

	.EXAMPLE
	Get-ProviderVdcStorageProfile -ProviderVdcName "*"

	Returns a collection of all Provider VDC Storage Policies which are accessible in the currently logged in users scope.

	.EXAMPLE
	Get-ProviderVdcStorageProfile -ProviderVdcName "New York Datacenter 1"

	Returns a collection of all Provider VDC Storage Policies defined on Provider VDC "New York Datacenter 1"

 	.EXAMPLE
	Get-ProviderVdcStorageProfile -ProviderVdcId "urn:vcloud:providervdc:2cbb70a6-2bb7-4fa6-a140-dd3dc5d93e0e"

	Returns the Provider VDC Storage Policies defined on the the Provider VDC with the vCloud Object Id urn:vcloud:providervdc:2cbb70a6-2bb7-4fa6-a140-dd3dc5d93e0e

	.EXAMPLE
	Get-ProviderVdcStorageProfile -Id "urn:vcloud:vdcstorageProfile:0a6b3ef2-00e6-43ae-889c-4922a39db21f"

	Returns the object for the Org VDC Storage Profile with the vCloud Object Id "urn:vcloud:vdcstorageProfile:0a6b3ef2-00e6-43ae-889c-4922a39db21f"

	.NOTES
	  NAME: Get-ProviderVdcStorageProfile
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-09-24
	#>
	[CmdletBinding(DefaultParameterSetName="ByName")]
	Param(
		[Parameter(Mandatory=$False,ParameterSetName = "ByName")]
			[ValidateNotNullorEmpty()] [string] $ProviderVdcName = "*",
		[Parameter(Mandatory=$True,ParameterSetName = "ProviderVdcId")]
			[ValidateNotNullorEmpty()] [string] $ProviderVdcId,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $Id
	)
	# Test to see if vCloud is connected
	if(!(Test-vCloudEnvironment)){
		Break
	}

	# Check if the user is logged into the System Org
	if($global:DefaultCIServers.Org -ne "System"){
		throw "You are not currently logged into vCloud under the System VDC Org. This cmdlet is only available to Provider Administrators."
	}
	# Declare a collection to store the Provider VDC Storage Profile objects returned by the function
	$colStorageProfiles = New-Object -TypeName System.Collections.ArrayList

	# Check if the cmdlet is targetting a ProviderVDC
	if($PSCmdlet.ParameterSetName -in ("ByName","ProviderVdcId")){
		# Build a collection of Provider VDC objects to query
		if($PSCmdlet.ParameterSetName -eq "ByName"){
			try{
				$colProviderVDC = Get-ProviderVdc -Name $ProviderVdcName
			} catch{
				throw "A Provider VDC could not be found with the name $ProviderVdcName. Please check the value and try again."
			}
		} elseif($PSCmdlet.ParameterSetName -eq "ProviderVdcId") {
			try{
				$colProviderVDC = Get-ProviderVdc -Id $ProviderVdcId
			} catch{
				throw "A Provider VDC could not be found with the Id $ProviderVdcId. Please check the value and try again."
			}
		}
		# Get the CI View for the returned objects
		$colProviderVDC = $colProviderVDC | Get-CIView
		foreach($ProviderVDC in $colProviderVDC){
			foreach($objProviderVdcStorageProfile in $ProviderVDC.StorageProfiles.ProviderVdcStorageProfile){
				# Make an API call to get the Properties for the Provider VDC Storage Profile
				$objProviderVDCStorageProfile = New-ProviderVdcStorageProfileObject -StorageProfileURI $objProviderVdcStorageProfile.href -ContentType $objProviderVdcStorageProfile.type
				$colStorageProfiles.Add($objProviderVDCStorageProfile) > $nul
			}
		}
	} elseif($PSCmdlet.ParameterSetName -eq "ById"){
		try{
			# Get the Storage Profile View
			$objStorageProfileViews = Get-CIView -Id $Id
		} catch {
			throw "A Storage Policy with the Id $Id could not be found. Please check the values and try again."
		}
		$objProviderVDCStorageProfile = New-ProviderVdcStorageProfileObject -StorageProfileURI $objStorageProfileViews.href -ContentType $objStorageProfileViews.type
		$colStorageProfiles.Add($objProviderVDCStorageProfile) > $nul
	}
	$colStorageProfiles
}

function Set-ProviderVdcStorageProfile(){
	<#
	.SYNOPSIS
	Allows the settings to be adjusted on a Provider VDC Storage Profile

	.DESCRIPTION
	Long description

	.PARAMETER ProviderVdcStorageProfile
	A collection of Provider VDC Storage Profiles returned from the Get-ProviderVdcStorageProfile cmdlet

	.PARAMETER ProviderVdcStorageProfileId
	The vCloud Object Id for the Provider VDC Storage Profile

	.PARAMETER Enabled
	If set to $true the Provider VDC Storage Profile is set to Enabled; if set to $false the Provider VDC Storage Profile will be disabled

    .EXAMPLE
    Set-ProviderVdcStorageProfile -ProviderVdcStorageProfile (Get-ProviderVdcStorageProfile -ProviderVdcName "New York Datacenter 1") -Enabled $false

    Will disable all of the Storage Profiles defined in the ProviderVdc New York Datacenter1

    .EXAMPLE
    Set-ProviderVdcStorageProfile -ProviderVdcStorageProfileId "urn:vcloud:vdcstorageProfile:0a6b3ef2-00e6-43ae-889c-4922a39db21f" -Enabled $true

	Will enable the Provider VDC Storage Profile with the vCloud Object Id "urn:vcloud:vdcstorageProfile:0a6b3ef2-00e6-43ae-889c-4922a39db21f"

	.NOTES
	  NAME: Set-ProviderVdcStorageProfile
	  AUTHOR: Adrian Begg
	  LASTEDIT: 2017-10-18
	#>
	Param(
		[Parameter(Mandatory=$True,ParameterSetName = "ByObject", ValueFromPipeline=$True)]
			[ValidateNotNullorEmpty()] [PSObject[]] $ProviderVdcStorageProfile,
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNullorEmpty()] [string] $ProviderVdcStorageProfileId,
		[Parameter(Mandatory=$True,ParameterSetName = "ByObject")]
		[Parameter(Mandatory=$True,ParameterSetName = "ById")]
			[ValidateNotNull()] [bool] $Enabled
	)
	# Process block is required for pipeline processing
	Process{
		# Get the CI-View objects
		$colProviderVDCStorageProfiles = New-Object -TypeName System.Collections.ArrayList
		if($PSCmdlet.ParameterSetName -in ("ById")){
			$colProviderVDCStorageProfiles.Add((Get-CIView -Id $ProviderVdcStorageProfileId)) > $nul
		} else {
			foreach($objStorageProfile in $ProviderVdcStorageProfile){
				$colProviderVDCStorageProfiles.Add((Get-CIView -Id $objStorageProfile.Id)) > $nul
			}
		}
		foreach($objProviderStorageProfileView in $colProviderVDCStorageProfiles){
			if(!($objProviderStorageProfileView.Enabled -eq $Enabled)){
				try{
					$objProviderStorageProfileView.Enabled = $Enabled
					$objProviderStorageProfileView.UpdateServerData() > $null
					Get-ProviderVdcStorageProfile -Id $objProviderStorageProfileView.Id
				} catch {
					throw "An error occured whilst applying the changes to the requested Storage Profile."
				}
			} else {
				Write-Warning "The Provider VDC Storage Profile already is set to Enabled $Enabled. No changes have been made."
			}
		}
	}
}
#endregion
