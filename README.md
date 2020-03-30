# AZFW.NSG.LogViewer

## Synopsis

A PowerShell module for quickly generating HTML reports from Azure Firewall or NSG logs.

## Screenshots

![New-AZFWLogReport](/screenshots/azfwlogreport.png "Azure Firewall log report")

![New-NSGLogReport](/screenshots/nsglogreport.png "NSG log report")

## Install

Please ensure you're running PowerShell version 5.1 or later.

This module can be installed from the [PowerShell gallery](https://www.powershellgallery.com/packages/AZFW.NSG.LogViewer):

`Install-Module AZFW.NSG.LogViewer`

### Pre-requisites

You will require:
* PowerShell 5.1 or later
* [Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-3.6.1) (Az) modules

To use the `-Console` flag, you'll need Powershell Core and the **Microsoft.PowerShell.ConsoleGuiTools** module.

`Install-Module Microsoft.PowerShell.ConsoleGuiTools`


If you're on Mac/Linux, you might also need the **Microsoft.PowerShell.GraphicalTools** module.

`Install-Module Microsoft.PowerShell.GraphicalTools`

### Configuring NSG logging

To generate NSG log reports, you must first have NSG flow logging configured. Please refer to the following documentation:

https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview


### Configuring Azure Firewall logging

To generate Azure Firewall log reports, Azure Firewall logging must be enabled. Please refer to the following documentation:

https://docs.microsoft.com/en-us/azure/firewall/tutorial-diagnostics

## Examples

`Get-AzVM -ResourceGroupName contoso -Name vm1 | New-NSGLogReport -Last 2`

`Get-AzVM -ResourceGroupName contoso -Name vm1 | New-NSGLogReport -Last 2 -BeforeDate '2020-03-29 18:00'`

`New-NSGLogReport -ResourceGroupName contoso -Name vm1`

`New-NSGLogReport -ResourceGroupName contoso -Name vm1 -Console`

`New-AZFWLogReport -StorageAccountName constosofwlogs -Last 2`

`New-AZFWLogReport -StorageAccountName constosofwlogs -Last 2 -BeforeDate '2020-03-29 18:00'`

`New-AZFWLogReport -StorageAccountName constosofwlogs -Console`