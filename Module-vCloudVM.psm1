##########################################################################################
# Name: Module-vCloudVM.psm1
# Created: Adrian Begg (2/5/2017) v1.0 (adrian.begg@ehloworld.com.au)
#
# Purpose: PowerShell modules to extend the PowerCLI for vCloud to expose
# additional methods for Virtual Machine objects uisng the vCloud REST API 
##########################################################################################

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
#>
	Param(
		[Parameter(Mandatory=$True)] [PSObject[]] $CIObject
	)	
	$objVMView = $CIObject | Get-CIView
	# Setup Web Request for the API call to retireve the Hardware Section for the VM
	$URI = ($objVMView.Href + "/virtualHardwareSection")
	$webclient = New-Object system.net.webclient
	$webclient.Headers.Add("x-vcloud-authorization",$objVMView.Client.SessionKey)
	$webclient.Headers.Add("Accept", "application/*+xml;version=5.1")
	[xml]$VMHardwarConfigXML = $webclient.DownloadString($URI)
	
	# If a CD/DVD is connected the HostResoruce will contain a path for Resoruce type 15 device
	((($VMHardwarConfigXML.VirtualHardwareSection.Item | ?{$_.ResourceType -eq 15}).HostResource) -ne "")
}
