# vCloud
A set of modules/scripts to extend the PowerCLI for vCloud

# Modules:
* Module-vCloudVM.psm1 : Additional functions for exposing virtual machine properties under PowerCLI Module for vCloud Director v8.xx

# Scripts:
* VMWare-vCloud-FixStorageProfiles.ps1 - The purpose of this script is to correct/set the storage profiles in vCenter to match the storage profile defined in vCloud Director. This is to fix an issue in the vCenter upgrade to vCenter 6.0 which causes mismatches to occur between vCloud and vSphere.
