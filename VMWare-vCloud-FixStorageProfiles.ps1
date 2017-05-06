##########################################################################################
# Name: VMWare-vCloud-FixStorageProfiles.ps1
# Author: Adrian Begg (adrian.begg@ehloworld.com.au)
# Date: 16/04/2017
#
# Purpose: The purpose of this script is to correct/set the storage profiles in vCenter to
# match the storage profile defined in vCloud Director. This is to fix an issue in the vCenter
# upgrade to vCenter 6.0 which causes mismatches to occur between vCloud and vSphere.
# 
##########################################################################################
# Change Log
# v0.1 - 16/4/2017 - Inital design
# v0.2 - 6/5/2017 - Redesigned and simplified after testing and additional module dev
##########################################################################################
# Tested on the following stacks:
# - vCloud Director for Service Providers 8.20 with vCenter 6.5a
# - vCloud Director for Service Providers 8.10 with vCenter 6.0 U5
#
# BEWARE: My testing should not be a substitue for your own !
##########################################################################################
# Requires vCloud and vSphere administrator rights
# Requires Module-vCloudVM.psm1 (https://github.com/AdrianBegg/vCloud/blob/master/Module-vCloudVM.psm1)
##########################################################################################

[string] $vcd = "vcd.pigeonnuggets.com"
[bool] $queryOnly = $true  # If set to false the script will go through and attempt to correct the issues
[string] $VirtualMachine = "*" # The VirtualMachine name to query/correct (use * for all VMs)

Import-Module ".\Module-vCloudVM.psm1"

# Connect to vCloud Director and query the Storage Profile for each of the disks
Connect-CIServer $vcd -Org System
$colVMs = Search-Cloud -QueryType AdminVM -Name $VirtualMachine

# Decalre a collection for storing the StorageProfile Configuarations for each VM
$colVMStorageConfig = New-Object -TypeName System.Collections.ArrayList

foreach($vm in $colVMs){
	# First check if the VM is a template and don't continue if it is
	if(!$vm.IsVAppTemplate){
		# Declare an object to store the information for processing
		$objVMConfiguration = New-Object System.Management.Automation.PSObject
		$objVMView = $vm | Get-CIView
	
		$objVMConfiguration | Add-Member Noteproperty VMRef $vm # The VM object which will be used for comparing in vSphere
		$objVMConfiguration | Add-Member Noteproperty vCenterURI (Get-CIVMvCenterURI $vm) # URI for the vCenter backing the VM
		$objVMConfiguration | Add-Member Noteproperty DefaultStorageProfile (Get-CIStorageProfileId $vm) # Get the default storage profile for the VM

		# Next we want to look for per disk overides on the disks for the Storage Profiles and build a collection for updates
		$colVMDisks = New-Object -TypeName System.Collections.ArrayList
		$colVMDisks = (Get-CIHardDisks $vm)
		# Set the propoerty
		$objVMConfiguration | Add-Member Noteproperty VMDiskCollection $colVMDisks
		
		# Add the configuration for the VM to the collection
		$colVMStorageConfig.Add($objVMConfiguration) > $nul
	}
}

# Now; update the objects in vCenter that don't match
foreach($objVM in $colVMStorageConfig){
	# Connect the the vCenter hosting the VM
	Connect-VIServer (([System.Uri]$objVM.vCenterURI).DnsSafeHost) > $nul
	$vCenterVM = $objVM.VMRef | Get-CIView | Get-View
	
	# Get the Storage Policy for the VM object
	$storageVMProfile = Get-SpbmEntityConfiguration -VM $($vCenterVM.Name)
	# Check if the default/VM storage policy does not match and update
	if(($storageVMProfile.StoragePolicy.Id) -ne $objVM.DefaultStorageProfile){
		if($queryOnly){
			Write-Host "Configuration mismatch detected on $($vCenterVM.Name) expected Storage Policy with ID $($objVM.DefaultStorageProfile) actual value: $($storageVMProfile.StoragePolicy.Id)"
		} else {
			# Update the profile
			$result = Set-SpbmEntityConfiguration -StoragePolicy (Get-SpbmStoragePolicy -Id $objVM.DefaultStorageProfile) -Configuration $storageVMProfile
		}
	}
	# Next get the Storage Policies for the Disks
	$vCenterDisks = Get-HardDisk ($vCenterVM.Name)
	$storageDiskProfile = Get-SpbmEntityConfiguration -Disk $vCenterDisks
	foreach($vmDisk in $objVM.VMDiskCollection){
		# Find the Disk in the StorageDiskProfile collection from vCenter that matches the vCloud Disk
		$matchDisk = $storageDiskProfile | ?{$_.Entity.Name -eq $vmDisk.HardDisk}
		# Check that a storage policy is set otherwise don't set $spIDcurrent (no point)
		if($($matchDisk.StoragePolicy).Id -ne $null){
			$spIDcurrent = (Get-SpbmStoragePolicy -Id $($matchDisk.StoragePolicy).Id)
		}
		if($spIDcurrent.Id -ne $vmDisk.StorageProfileID){
			if($queryOnly){
				Write-Host "Configuration mismatch detected on $($vmDisk.HardDisk) for $($vCenterVM.Name) - vCenter Storage Profile: $spIDcurrent vCloud Expected: $($vmDisk.StorageProfileID)"
			} else {
				$result = Set-SpbmEntityConfiguration -StoragePolicy (Get-SpbmStoragePolicy -Id $vmDisk.StorageProfileID) -Configuration $matchDisk
			}
		}
	}
	# Close the connection to vCenter
	Disconnect-VIServer -Confirm:$false
}
# Close the connection to vCloud Director
Disconnect-CIServer -Confirm:$false
