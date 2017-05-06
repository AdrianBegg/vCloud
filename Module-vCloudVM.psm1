##########################################################################################
# Name: Module-vCloudVM.psm1
# Date: 27/03/2017 (v0.2)
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
# 
# Purpose: PowerShell modules to extend the PowerCLI for vCloud to expose
# additional methods for Virtual Machine objects uisng the vCloud REST API 
##########################################################################################
# Change Log
# v0.1 - 2/5/2017 - Created module from a series of individual script functions
# v0.2 - 6/5/2017 - Extended and added Storage Profile and Virtual HDD functions and redesigned API GET methods
##########################################################################################

#region: SupportFunctions
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
	$webclient.Headers.Add("Accept", "application/*+xml;version=5.6")
	$webclient.Headers.Add("Content-Type", $ContentType)
	try{
		[xml]$xmlResponse = $webclient.DownloadString($URI)
	} catch {
		throw "An error occured attempting to make HTTP GET against $URI"
	}		
	$xmlResponse
}
#endregion

#region: Hardware
function Get-VMCDROMMounted(){
<#
.SYNOPSIS
Returns true if a CD/DVD is connected to a VM in vCloud Director

.DESCRIPTION
A function to determine if a CD/DVD ISO is mounted to a machine in vCloud Director

.PARAMETER CIObject
The Virtual Machine object (PowerCLI CIObject)

.EXAMPLE
Get-VMCDROMMounted (Get-CIVM "SERVER1") 

Returns true if a CD/DVD is connected to Virtual Machine SERVER1 in vCloud tenancy.

.NOTES
  NAME: Get-VMCDROMMounted
  AUTHOR: Adrian Begg
  LASTEDIT: 2017-05-05
  KEYWORDS: vmware get vcloud director cdrom iso
  #Requires -Version 2.0
#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject[]] $CIObject
	)	
	$objVMView = $CIObject | Get-CIView
	# Setup Web Request for the API call to retireve the Hardware Section for the VM
	$URI = ($objVMView.Href + "/virtualHardwareSection")
	[xml]$VMHardwarConfigXML = Get-vCloudAPIResponse -URI $URI -SessionKey $objVMView.Client.SessionKey -ContentType "application/vnd.vmware.vcloud.virtualHardwareSection+xml"

	# If a CD/DVD is connected the HostResoruce will contain a path for Resoruce type 15 device
	((($VMHardwarConfigXML.VirtualHardwareSection.Item | ?{$_.ResourceType -eq 15}).HostResource) -ne "")
}

function Get-CIHardDisks(){
<#
.SYNOPSIS
Returns an ArrayList (collection) of vCloud Director Hard Disks attached to a provided CIVM

.DESCRIPTION
Returns an ArrayList (collection) of vCloud Director Hard Disks attached to a provided CIVM

.PARAMETER CIObject
The Virtual Machine object

.EXAMPLE
Get-CIHardDisks (Get-CIVM "SERVER1") 

Returns a collection of virtual disks attached to the virtual machine.
#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject[]] $CIObject
	)
	# Get the required info for API calls
	$objVMView = $CIObject | Get-CIView
	$colVMDisks = New-Object -TypeName System.Collections.ArrayList
	
	# Setup Web Request for the API call
	$URI = ($objVMView.Href + "/virtualHardwareSection/disks")
	[xml]$VMDiskConfigXML = Get-vCloudAPIResponse -URI $URI -SessionKey $objVMView.Client.SessionKey -ContentType "application/vnd.vmware.vcloud.rasditemslist+xml"
	
	# Get the default storage ProfileId
	$objDefaultStorageProfile = (Get-CIStorageProfileId $CIObject)
	foreach($objDisk in $VMDiskConfigXML.RasdItemsList.Item){
		if($objDisk.ResourceType -eq 17){
			$objVMDisk = New-Object System.Management.Automation.PSObject
			$objVMDisk | Add-Member Noteproperty HardDisk $objDisk.ElementName # This propoerty is unique to vCloud and vSphere
			$objVMDisk | Add-Member Noteproperty AddressOnParent $objDisk.AddressOnParent
			$objVMDisk | Add-Member Noteproperty VirtualQuantityBytes $objDisk.VirtualQuantity
			if($objDisk.HostResource.storageProfileOverrideVmDefault -eq "true"){
				# Get the Storage Profile UID
				[xml]$xmlHDDStorageProfile = Get-vCloudAPIResponse -URI $objDisk.HostResource.storageProfileHref -SessionKey $objVMView.Client.SessionKey -ContentType "application/vnd.vmware.vcloud.vdcStorageProfile+xml"
				# Add the globally unique Id of the Storage Profile which is backing the Storage profile in vCenter (Get-SpbmStoragePolicy | fl id)
				$objVMDisk | Add-Member Noteproperty StorageProfileID (Search-Cloud -querytype AdminOrgVdcStorageProfile | ?{($_.Id -eq $xmlHDDStorageProfile.VdcStorageProfile.id)}).StorageProfileMoref
			} else {
				$objVMDisk | Add-Member Noteproperty StorageProfileID $objDefaultStorageProfile
			}
			$colVMDisks.Add($objVMDisk) > $nul
		}
	}
	# Return the collection
	$colVMDisks
}
#endregion

#region: Backend Resources
function Get-CIVMvCenterURI{
<#
.SYNOPSIS
Returns the URI of the vCenter that hosts vCloud Director Virtual Machine

.DESCRIPTION
Returns the URI of the vCenter that hosts vCloud Director Virtual Machine

.PARAMETER CIObject
The Virtual Machine object

.EXAMPLE
Get-CIVMvCenterURI (Get-CIVM "SERVER1") 

Returns the URI of the vCenter that hosts the virtual machine.
#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject[]] $CIObject
	)
	# Setup Web Request for the API call to retireve the vCenter for the VM
	$objVMView = $CIObject | Get-CIView
	[xml]$vCenterServerXML = Get-vCloudAPIResponse -URI $objVMView.VCloudExtension.Any.VmVimObjectRef.VimServerRef.href -SessionKey $objVMView.Client.SessionKey -ContentType "application/vnd.vmware.admin.vmwvirtualcenter+xml"
	
	# Return the vCenter URI
	$vCenterServerXML.VimServer.Url
}

function Get-CIStorageProfileId(){
<#
.SYNOPSIS
Returns the Globally Unique ID of the Storage Profile assigned to a CIVM

.DESCRIPTION
Returns the Globally Unique ID  of the Storage Profile which is backing a vCloud Storage profile in vCenter for a virtual machine or virtual disk

.PARAMETER CIObject
The Virtual Machine or CI Virtual Disk

.EXAMPLE
Get-CIStorageProfileId (Get-CIVM "SERVER1") 

Returns the Storage Profile Id of the default Storage Profile assigned to SERVER1 in vCloud Director

Get-CIStorageProfileId $vmDisk1 

Returns the Storage Profile Id of the Storage Profile assigned to object $VMDisk1 in vCloud Director
#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject[]] $CIObject
	)
	# Get the required info for API calls
	$objVMView = $CIObject | Get-CIView
	[xml]$DefautlSPXML = Get-vCloudAPIResponse -URI $objVMView.StorageProfile.Href -SessionKey $objVMView.Client.SessionKey -ContentType "application/vnd.vmware.vcloud.vdcStorageProfile+xml"
	
	# This is the globally unique Id of the Storage Profile which is backing the Storage profile in vCenter (Get-SpbmStoragePolicy | fl id)
	(Search-Cloud -querytype AdminOrgVdcStorageProfile | ?{($_.Id -eq $DefautlSPXML.VdcStorageProfile.id)}).StorageProfileMoref
}
#endregion

#region: Metadata
Function New-CIMetaData { 
    <# 
    .SYNOPSIS 
        Creates a Metadata Key/Value pair. 
    .DESCRIPTION 
        Creates a custom Metadata Key/Value pair on a specified vCloud object 
    .PARAMETER  Key 
        The name of the Metadata to be applied.
    .PARAMETER  Value
        The value of the Metadata to be applied, the string 'Now' can be used
        for the current date/time for values using the 'DateTime' type.
    .PARAMETER  Visibility
        The visibility of the Metadata entry (General, Private, ReadOnly)
    .PARAMETER  Type
        The type of the Metadata entry (String, Number, DateTime, Boolean)
        (these correspond to the types of: MetadataStringValue,
        MetadataNumberValue, MetadataDateTimeValue or MetadataBooleanValue
        respectively)
    .PARAMETER  CIObject
        The object on which to apply the Metadata.
    .EXAMPLE
        New-CIMetadata -Key "Owner" -Value "Alan Renouf" -CIObject (Get-Org Org1)
        Creates a new metadata value "Alan Renouf" in a key "Owner" on the Org1 object.
    .EXAMPLE
        New-CIMetadata -Key "Company" -Value "ABC Corp" -Visibility READONLY -CIObject (Get-CIVM 'client')
        Creates a new metadata value "ABC Corp" in a key "Company" on the 'client' VM object with the READONLY attribute set preventing changes by non-system users.
    .EXAMPLE
        New-CIMetadata -Key "Backup" -Value $false -Visibility Private -Type Boolean -CIObject (Get-CIVapp 'testvapp')
        Creates a new hidden metadata value $false in a key "Backup" on the vApp object with the 'Private' attribute set preventing visibility to non-system users.
    .NOTES
        NAME: New-CIMetaData
        AUTHOR: Jon Waite based on code by Alan Renouf
        LASTEDIT: 2016-02-23
        KEYWORDS: metadata set vcloud director
    #Requires -Version 2.0
    #> 
     [CmdletBinding( 
         SupportsShouldProcess=$true, 
        ConfirmImpact="High" 
    )] 
    param( 
        [parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)] 
            [PSObject[]]$CIObject, 
        [parameter(Mandatory=$true)]
            [String]$Key,
        [parameter(Mandatory=$true)]
            $Value,
        [ValidateSet('General','Private','ReadOnly')]
            [String]$Visibility = 'General',
        [ValidateSet('String','Number','DateTime','Boolean')]
            [String]$Type = "String"
        ) 
    Process { 
        Foreach ($Object in $CIObject) { 
            $Metadata = New-Object VMware.VimAutomation.Cloud.Views.Metadata 
            $Metadata.MetadataEntry = New-Object VMware.VimAutomation.Cloud.Views.MetadataEntry 
            
            $Metadata.MetadataEntry[0].Key = $Key
 
            switch($Type) {
              'String'   { $Metadata.MetadataEntry[0].TypedValue = New-Object VMware.VimAutomation.Cloud.Views.MetadataStringValue }
              'Number'   { $Metadata.MetadataEntry[0].TypedValue = New-Object VMware.VimAutomation.Cloud.Views.MetadataNumberValue }
              'DateTime' { $Metadata.MetadataEntry[0].TypedValue = New-Object VMware.VimAutomation.Cloud.Views.MetadataDateTimeValue }
              'Boolean'  { $Metadata.MetadataEntry[0].TypedValue = New-Object VMware.VimAutomation.Cloud.Views.MetadataBooleanValue }
            }
 
            if ($Type -eq 'DateTime' -and $Value -eq 'Now') {
                $Metadata.MetadataEntry[0].TypedValue.Value = [string](Get-Date).ToUniversalTime().GetDateTimeFormats('s')
            } else {
                $Metadata.MetadataEntry[0].TypedValue.Value = $Value
            }
            
            switch($Visibility) {
              'General'  { } #Default, don't need to change
              'Private'  { 
                $Metadata.MetadataEntry[0].Domain = New-Object VMware.VimAutomation.Cloud.Views.MetadataDomainTag
                $Metadata.MetadataEntry[0].Domain.Value = 'SYSTEM'
                $Metadata.MetadataEntry[0].Domain.Visibility = 'PRIVATE'
                }
              'ReadOnly' {
                $Metadata.MetadataEntry[0].Domain = New-Object VMware.VimAutomation.Cloud.Views.MetadataDomainTag
                $Metadata.MetadataEntry[0].Domain.Value = 'SYSTEM'
                $Metadata.MetadataEntry[0].Domain.Visibility = 'READONLY'
                }      
            }
 
            $Object.ExtensionData.CreateMetadata($Metadata) 
            ($Object.ExtensionData.GetMetadata()).MetadataEntry | Where {$_.Key -eq $key } | Select @{N="CIObject";E={$Object.Name}},
            @{N="Type";E={$_.TypedValue.GetType().Name}},
            @{N="Visibility";E={ if ($_.Domain.Visibility) { $_.Domain.Visibility } else { "General" }}},
            Key -ExpandProperty TypedValue
        } 
    } 
} 
Function Get-CIMetaData {
    <#
    .SYNOPSIS
        Retrieves all Metadata Key/Value pairs.
    .DESCRIPTION
        Retrieves all custom Metadata Key/Value pairs on a specified vCloud object
    .PARAMETER  CIObject
        The object on which to retrieve the Metadata.
    .PARAMETER  Key
        The key to retrieve.
    .EXAMPLE
        Get-CIMetadata -CIObject (Get-Org Org1)
    .NOTES
        NAME: Get-CIMetaData
        AUTHOR: Jon Waite based on code by Alan Renouf
        LASTEDIT: 2016-02-23
        KEYWORDS: metadata set vcloud director
    #Requires -Version 2.0
    #>
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
            [PSObject[]]$CIObject,
            $Key
        )
    Process {
        Foreach ($Object in $CIObject) {
            If ($Key) {
                ($Object.ExtensionData.GetMetadata()).MetadataEntry | Where {$_.Key -eq $key } | Select @{N="CIObject";E={$Object.Name}},
                    @{N="Type";E={$_.TypedValue.GetType().Name}},
                    @{N="Visibility";E={ if ($_.Domain.Visibility) { $_.Domain.Visibility } else { "General" }}},
                    Key -ExpandProperty TypedValue
            } Else {
                ($Object.ExtensionData.GetMetadata()).MetadataEntry | Select @{N="CIObject";E={$Object.Name}},
                    @{N="Type";E={$_.TypedValue.GetType().Name}},
                    @{N="Visibility";E={ if ($_.Domain.Visibility) { $_.Domain.Visibility } else { "General" }}},
                    Key -ExpandProperty TypedValue
            }
        }
    }
}
Function Remove-CIMetaData {
    <#
    .SYNOPSIS
        Removes a Metadata Key/Value pair.
    .DESCRIPTION
        Removes a custom Metadata Key/Value pair on a specified vCloud object
    .PARAMETER  Key
        The name of the Metadata to be removed.
    .PARAMETER  CIObject
        The object on which to remove the Metadata.
    .EXAMPLE
        Remove-CIMetaData -CIObject (Get-Org Org1) -Key "Owner"
    .NOTES
        NAME: Remove-CIMetaData
        AUTHOR: Jon Waite based on code by Alan Renouf
        LASTEDIT: 2016-02-23
        KEYWORDS: metadata set vcloud director
    #Requires -Version 2.0
	#>
     [CmdletBinding(
         SupportsShouldProcess=$true,
        ConfirmImpact="High"
    )]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
            [PSObject[]]$CIObject,
            $Key
        )
    Process {
        $CIObject | Foreach {
            $metadataValue = ($_.ExtensionData.GetMetadata()).GetMetaDataValue($Key)
            If($metadataValue) { $metadataValue.Delete() }
        }
    }
}
#endregion

#region: State
function Invoke-VMOperation(){
<#
.SYNOPSIS
Performs an operation against the provided vCloud Director CIObject

.DESCRIPTION
Allows for a Start, Stop, Suspend or Shutdown of the Guest OS of a vCloud Director virtual machine or vApp

.PARAMETER CIObject
The Virtual Machine object or vApp (PowerCLI CIObject)

.PARAMETER Operation
The operation to perform; valid Operations: Start, ShutdownGuest, Suspend, Stop

.EXAMPLE
Invoke-VMOperation (Get-CIVM "SERVER1") "Start"

Starts the VM SERVER1.

.NOTES
  NAME: Invoke-VMOperation
  AUTHOR: Adrian Begg
  LASTEDIT: 2017-04-05
  KEYWORDS: vmware vcloud director
  #Requires -Version 2.0
#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject[]] $CIObject,
		[ValidateSet('Start','ShutdownGuest','Suspend','Stop')]
			[Parameter(Mandatory=$True)] [string] $Operation
	)
	# A check for the type of object
	[bool] $objVMType = $true;
	if($CIObject.ExtensionData.Type -eq "application/vnd.vmware.vcloud.vm+xml"){
		$objVMType = $true;
	} elseif($CIObject.ExtensionData.Type -eq "application/vnd.vmware.vcloud.vApp+xml"){
		$objVMType = $false;
	}
	if($Operation -eq "ShutdownGuest"){
		if($objVMType){
			try{
				Stop-CIVMGuest $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Shutdown Guest Operation against Virtual Machine $($CIObject.Name)"
			}
		} else {
			try{
				Stop-CIVappGuest $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Shutdown Guest Operation against vApp $($CIObject.Name)"
			}
		}
	}
	if($Operation -eq "Start"){
		if($objVMType){
			try{
				$result = Start-CIVM $CIObject -Confirm:$false
				if(Get-VMCDROMMounted $CIObject){
					# Send a warning that a CD/DVD is mounted to the VM
				}
			} catch {
				throw "An error occured attempting Start of Virtual Machine $($CIObject.Name)"
			}
		} else {
			try{
				$result = Start-CIVApp $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Start of vApp $($CIObject.Name)"
			}
		}
	}
	if($Operation -eq "Stop"){
		if($objVMType){
			try{
				$result = Stop-CIVM $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Stop of Virtual Machine $($CIObject.Name)"
			}
		} else {
			try{
				$result = Stop-CIVApp $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Stop of vApp $($CIObject.Name)"
			}
		}
	}
	if($Operation -eq "Suspend"){
		if($objVMType){
			try{
				$result = Suspend-CIVM $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Stop of Virtual Machine $($CIObject.Name)"
			}
		} else {
			try{
				$result = Suspend-CIVApp $CIObject -Confirm:$false
			} catch {
				throw "An error occured attempting Stop of vApp $($CIObject.Name)"
			}
		}
	}
}
#endregion
