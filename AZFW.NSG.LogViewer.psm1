Function Get-StorageAccountBlobsAPI {

    param(
        [string]$StorageAccountName,
        [string]$Container,
        [string]$StorageKey
    )

    $request_uri = New-Object System.Uri ('https://{0}.blob.core.windows.net/{1}?restype=container&comp=list' -f $StorageAccountName, $Container)

    $date_string = (Get-Date).ToString('R',[System.Globalization.CultureInfo]::InvariantCulture)

    $headers = @{
        'x-ms-date' = $date_string
        'x-ms-version' = '2019-02-02'
    }

    $canonicalized_string = "GET`n`n`n`nx-ms-date:$date_string`nx-ms-version:2019-02-02`n/$($StorageAccountName)/$($Container)?comp=list"

    [byte[]]$key = [Convert]::FromBase64String($StorageKey)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 @(,$key)
    [byte[]]$hmac_data = [System.Text.Encoding]::UTF8.GetBytes($canonicalized_string)
    $signature = [Convert]::ToBase64String($hmac.ComputeHash($hmac_data))

    $headers['Authorization'] = ('SharedKeyLite {0}:{1}' -f $StorageAccountName, $signature)

    $result = Invoke-RestMethod -Uri $request_uri -Headers $headers -TimeoutSec 120

    $bom = ([char[]][byte[]]@(239,187,191)) -join ''

    $xml = [xml]($result -replace "^$bom", '')

    $return_obj = @()

    $xml.EnumerationResults.Blobs.Blob | %{
        $blob_obj = New-Object PSObject
        $blob_obj | Add-Member -Type NoteProperty -Name 'Name' -Value $_.Name
        $blob_obj | Add-Member -Type NoteProperty -Name 'LastModified' -Value $_.Properties.'Last-Modified'
        $return_obj += $blob_obj
    }

    Return $return_obj

}

Function Get-StorageAccountBlobContentAPI {

    param(
        [string]$StorageAccountName,
        [string]$Container,
        [string]$BlobName,
        [string]$StorageKey
    )

    $request_uri = New-Object System.Uri ('https://{0}.blob.core.windows.net/{1}/{2}' -f $StorageAccountName, $Container, $BlobName)

    $date_string = (Get-Date).ToString('R',[System.Globalization.CultureInfo]::InvariantCulture)

    $headers = @{
        'x-ms-date' = $date_string
        'x-ms-version' = '2019-02-02'
    }

    $canonicalized_string = "GET`n`n`n`nx-ms-date:$date_string`nx-ms-version:2019-02-02`n/$($StorageAccountName)/$($Container)/$($BlobName)"

    [byte[]]$key = [Convert]::FromBase64String($StorageKey)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 @(,$key)
    [byte[]]$hmac_data = [System.Text.Encoding]::UTF8.GetBytes($canonicalized_string)
    $signature = [Convert]::ToBase64String($hmac.ComputeHash($hmac_data))

    $headers['Authorization'] = ('SharedKeyLite {0}:{1}' -f $StorageAccountName, $signature)

    $result = Invoke-WebRequest -Uri $request_uri -Headers $headers

    Return $result.ToString()

}

Function Get-ModuleCompatability {

    param(
        [bool]$Console = $false,
        [bool]$Last = $false
    )

    If (!(Get-Module Az.Network -ListAvailable) -or !(Get-Module Az.Network -ListAvailable)) {
        Throw 'Install the Azure (Az) modules to use this tool'
    }
    If (!$Last) {
        If ($Console -and !(Get-Module Microsoft.PowerShell.ConsoleGuiTools -ListAvailable)) {
            Throw 'Install the module "Microsoft.PowerShell.ConsuleGuiTools" to use -Console. Or, specify the number of logs to load with -Last.'
        }
        If (!$Console -and !(Get-Module Microsoft.PowerShell.GraphicalTools -ListAvailable) -and $PSVersionTable.PSVersion.Major -ge 6 -and [Environment]::OSVersion.Platform -ne 'Win32NT') {
            Throw 'Install the module "Microsoft.PowerShell.GraphicalTools" to select logs via GUI in PowerShell Core. Or, specify the number of logs to load with -Last.'
        }
    }

}

Function New-NSGLogReport {

    <#
        .SYNOPSIS

        Generates a HTML report from NSG logs.

        .DESCRIPTION

        Downloads NSG flow logs, parses them, and generates a
        HTML report using ag-Grid.

        .PARAMETER ResourceGroupName
        The resource group containing the target virtual machine.

        .PARAMETER Name
        The name of the target virtual machine.

        .PARAMETER Last
        The number of previous, recent NSG logs to load. NSG logs are rotated hourly, on the hour.

        .PARAMETER Path
        The path to create the HTML report. Default is %TEMP%\nsg_report.htm

        .PARAMETER Console
        Use Out-ConsoleGridView instead of Out-GridView. Requires Microsoft.PowerShell.ConsoleGuiTools and Powershell Core 7 or newer.

        .INPUTS
        Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine
        A virtual machine object

        .OUTPUTS
        None

        .EXAMPLE

        Get-AzVM -ResourceGroupName contoso -Name vm1 | New-NSGLogReport -Last 2

        .EXAMPLE

        New-NSGLogReport -ResourceGroupName contoso -Name vm1

        .EXAMPLE

        New-NSGLogReport -ResourceGroupName contoso -Name vm1 -Console

    #>

    [CmdletBinding(DefaultParametersetname='Default')]
    param(

        [Parameter(Mandatory=$true,ParameterSetName='Default')]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true,ParameterSetName='Default')]
        [string]
        $Name,

        [Parameter(ValueFromPipeline=$true,Mandatory=$true,ParameterSetName='FromPipeline')]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $InputObject,

        [Parameter()]
        [int]
        $Last,

        [Parameter()]
        [string]
        $Path = "$env:TEMP\nsg_report.htm",

        [Parameter()]
        [switch]
        $Console

    )

    $ErrorActionPreference = 'Stop'

    $LOG_CONTAINER_NAME = 'insights-logs-networksecuritygroupflowevent'

    # Check module availability

    Get-ModuleCompatability -Console $Console -Last $Last

    # Load the VM object

    If ($PSCmdlet.ParameterSetName -eq 'Default') {
        Write-Host 'Loading VM ...'
        $vm_obj = Get-AzVM -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction Stop
    } Else {
        $vm_obj = $InputObject
    }

    # Retrieve the VM's NIC

    Write-Host 'Loading NIC ...'
    If ($vm_obj.NetworkProfile.NetworkInterfaces.Count -ne 1) {
        Throw 'This cmdlet only supports VMs with exactly 1 network interface.'
    }
    $nic_obj = Get-AzNetworkInterface -ResourceId $vm_obj.NetworkProfile.NetworkInterfaces[0].Id

    # Retrieve the VM's Subnet

    Write-Host "Loading subnet ..."
    $subnet_obj = Get-AzVirtualNetworkSubnetConfig -ResourceId $nic_obj.IpConfigurations[0].Subnet.Id

    # Retrieve NSG attached to NIC

    If ($nic_obj.IpConfigurations.Count -ne 1) {
        Throw 'This cmdlet only supports NICs with exactly 1 IP configuration.'
    }

    If (-not ($nic_obj.NetworkSecurityGroup.Id -or $subnet_obj.NetworkSecurityGroup.Id)) {
        Throw 'There is no NSG attached to either the NIC or its subnet'
    }
    
    If ($nic_obj.NetworkSecurityGroup.Id -and $subnet_obj.NetworkSecurityGroup.Id) {
        Write-Warning "A NSG is attached to both the NIC and its subnet. Only results from the NIC's NSG will be returned."
    }

    If ($nic_obj.NetworkSecurityGroup.Id) {
        $nsg_id = $nic_obj.NetworkSecurityGroup.Id
    } Else {
        $nsg_id = $subnet_obj.NetworkSecurityGroup.Id
    }
    Write-Host 'Loading NSG ...'
    $nsg_obj = Get-AzResource -ResourceId $nsg_id | Get-AzNetworkSecurityGroup

    # Retrieve network watcher

    Write-Host 'Loading network watcher ...'
    Try {
        $watcher_obj = Get-AzNetworkWatcher -Location $nsg_obj.Location -ErrorAction Stop
    } Catch {
        Throw "Could not retrieve network watcher for $($nsg_obj.Location). It is probably not configured."
    }

    # Retrieve log storage account

    Write-Host 'Loading logs storage account ...'
    $watcher_status = Get-AzNetworkWatcherFlowLogStatus -NetworkWatcher $watcher_obj -TargetResourceId $nsg_obj.Id
    $sa_obj = Get-AzResource -ResourceId $watcher_status.StorageId | Get-AzStorageAccount
    $sa_key = ($sa_obj | Get-AzStorageAccountKey)[0].Value

    # Retrieve log blobs

    Write-Host 'Finding log blobs ...'
    $nic_mac = $nic_obj.MacAddress -replace '-',''
    $blobs = Get-StorageAccountBlobsAPI -StorageAccountName $sa_obj.StorageAccountName -Container $LOG_CONTAINER_NAME -StorageKey $sa_key | ?{$_.Name -match $nic_mac}

    $nsg_log_timestamp_selection = @{
        n = 'LogTime'
        e = {
            $_.Name -match '\/y=(\d{4})\/m=(\d{1,2})\/d=(\d{1,2})\/h=(\d{1,2})\/m=(\d{1,2})\/macAddress=\w{12}\/PT1H.json$' > $null
            Return [datetime]"$($Matches[1])-$($Matches[2])-$($Matches[3]) $($Matches[4]):$($Matches[5])"
        }
    }
    $all_blobs = $blobs | Select $nsg_log_timestamp_selection, LastModified, Name | Sort-Object LastModified -Descending
    If ($Last) {
        $target_blobs = $all_blobs | Select -First $Last
    } Else {
        If ($Console) {
            $target_blobs = $all_blobs | Out-ConsoleGridView -PassThru
        } Else {
            $target_blobs = $all_blobs | Out-GridView -PassThru
        }        
    }

    [datetime]$origin = '1970-01-01 00:00:00'
    ForEach ($blob in $target_blobs) {
    
        # Download blob

        Write-Host "Downloading blob: $($blob.Name) ..."
        $nsg_log = Get-StorageAccountBlobContentAPI -StorageAccountName $sa_obj.StorageAccountName -Container $LOG_CONTAINER_NAME -BlobName $blob.Name -StorageKey $sa_key | ConvertFrom-Json

        # Parse JSON

        $output = @{
            nsg_data = [string[]]@()
        }

        Write-Host "Parsing blob: $($blob.Name)..."
        Write-Host "$($nsg_log.records.properties.flows.flows.flowtuples.Count) items to process..."
        ForEach ($flow in $nsg_log.records.properties.flows) {
            $rule = $flow.rule
            ForEach ($tuple in $flow.flows.flowTuples) {

                $nsg_flow_item = $tuple -split ','

                $time = ($origin.AddSeconds($nsg_flow_item[0])).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $rule = $rule
                $sourceIP = $nsg_flow_item[1]
                $destinationIP = $nsg_flow_item[2]
                $sourcePort = $nsg_flow_item[3]
                $destinationPort = $nsg_flow_item[4]
                $protocol = Switch ($nsg_flow_item[5]) { 'T' {'TCP'}; 'U' {'UDP'}; default {$nsg_flow_item[6]} }
                $direction = Switch ($nsg_flow_item[6]) { 'I' {'Inbound'}; 'O' {'Outbound'}; default {$nsg_flow_item[6]} }
                $allowed = Switch ($nsg_flow_item[7]) { 'A' {'Allow'}; 'D' {'Deny'}; default {$nsg_flow_item[6]} }

                $output.nsg_data += ("{{ time: '{0}', protocol: '{1}', source_ip: '{2}', source_port: {3}, destination_ip: '{4}', destination_port: {5}, direction: '{6}', allowed: '{7}', rule: '{8}' }}," -f `
                    $time, $protocol, $sourceIP, $sourcePort, $destinationIP, $destinationPort, $direction, $allowed, $rule)

            }

        }

    }

    # Init file stream

    If (Test-Path $Path) {Remove-Item $Path}
    $file_stream = New-Object System.IO.StreamWriter $Path

    # Write report file using template

    $report = Get-Content "$PSScriptRoot\template\nsg_report_template.htm"

    ForEach ($line in $report) {
        $line = [regex]::Replace($line,'{{ ([^\s]*) }}', { param($match) Return ($output."$($match.Groups[1].Value)" -join "`n") } )
        $file_stream.Write($line)
        $file_stream.Write("`n")
    }

    $file_stream.Close()

    & $Path
    
}

Function Parse-AZFWLog {

    param(
        [ref]$AZFWLog,
        [hashtable]$Output
    )

    ForEach ($line in ($AZFWLog.Value.Trim() -split "`n")) {

        $log = $line | ConvertFrom-Json

        $category = $log.category
        $time = ([datetime]$log.time).ToString('yyyy-MM-dd HH:mm:ss.fff')

        If ($category -eq 'AzureFirewallApplicationRule') {
            
            $msg = $log.properties.msg
            
            If ($msg -match '^(\S+)\s+request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) to (\S+):(\d{1,5})\. Action: (\S+)\. Rule collection: (\S+)\. Rule: ([^\.]+)$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $matches[4]
                $destination_port = $matches[5]
                $action = $matches[6]
                $rule_collection = $matches[7]
                $rule = $matches[8]
            } ElseIf ($msg -match '^(\S+)\s+request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) to (\S+):(\d{1,5})\. Action: (\S+)\. No rule matched. Proceeding with default action$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $matches[4]
                $destination_port = $matches[5]
                $action = $matches[6]
                $rule_collection = $null
                $rule = 'DEFAULT'
            } ElseIf ($msg -match '^(\S+)\s+request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) was denied\. Reason: (.+)$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $null
                $destination_port = $null
                $action = 'Deny'
                $rule_collection = $null
                $rule = "[$($matches[4])]"
            } ElseIf ($msg -match '^(\S+)\s+request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\. Action: Deny\. Reason: (.+)$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $null
                $destination_port = $null
                $action = 'Deny'
                $rule_collection = $null
                $rule = "[$($matches[4])]"
            } Else {
                Write-Warning "[AzureFirewallApplicationRule] Can not parse [$msg]"
                Return
            }

            $Output.applog_data += ("{{ time: '{0}', protocol: '{1}', source_ip: '{2}', source_port: '{3}', destination_ip: '{4}', destination_port: '{5}', action: '{6}', rule_collection: '{7}', rule: '{8}' }},`n" -f `
                $time, $protocol, $source_ip, $source_port, $destination_ip, $destination_port, $action, $rule_collection, $rule
            )

        } ElseIf ($category -eq 'AzureFirewallNetworkRule') {

            $msg = $log.properties.msg
            
            If ($msg -match '^(\S+) request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\. Action: (\S+)$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $matches[4]
                $destination_port = $matches[5]
                $action = $matches[6]
            } ElseIf ($msg -match '^(\S+) request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\. Action: (\S+)$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $null
                $destination_ip = $matches[3]
                $destination_port = $null
                $action = $matches[4]
            } ElseIf ($msg -match '^ICMP Type=(\d+) request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):*(\d{1,5})* to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):*(\d{1,5})*\. Action: (\S+)') {
                $protocol = "ICMP[$($matches[1])]"
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $matches[4]
                $destination_port = $matches[5]
                $action = $matches[6]
            } ElseIf ($msg -match '^(\S+) request from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\. Action: (.*)$') {
                $protocol = $matches[1]
                $source_ip = $matches[2]
                $source_port = $matches[3]
                $destination_ip = $matches[4]
                $destination_port = $matches[5]
                $action = $matches[6]
            } Else {
                Write-Warning "[AzureFirewallNetworkRule] Can not parse [$msg]"
                Return
            }

            $Output.netlog_data += ("{{ time: '{0}', protocol: '{1}', source_ip: '{2}', source_port: '{3}', destination_ip: '{4}', destination_port: '{5}', action: '{6}' }},`n" -f `
                $time, $protocol, $source_ip, $source_port, $destination_ip, $destination_port, $action
            )

        } Else {
            Write-Warning "Can not parse unknown category [$($category)]"
        }

    }

}

Function New-AZFWLogReport {

    <#
        .SYNOPSIS

        Generates a HTML report from Azure Firewall logs.

        .DESCRIPTION

        Downloads Azure Firewall logs, parses them, and generates a
        HTML report using ag-Grid.

        .PARAMETER StorageAccountName
        The storage account containing Azure Firewall logs.

        .PARAMETER Last
        The number of previous, recent NSG logs to load. NSG logs are rotated hourly, on the hour.

        .PARAMETER Path
        The path to create the HTML report. Default is %TEMP%\azfw_report.htm

        .PARAMETER Console
        Use Out-ConsoleGridView instead of Out-GridView. Requires Microsoft.PowerShell.ConsoleGuiTools and Powershell Core 7 or newer.

        .INPUTS
        None

        .OUTPUTS
        None

        .EXAMPLE

        New-AZFWLogReport -StorageAccountName constosofwlogs -Last 2

        .EXAMPLE

         New-AZFWLogReport -StorageAccountName constosofwlogs

        .EXAMPLE

         New-AZFWLogReport -StorageAccountName constosofwlogs -Console

    #>

    param(

        [Parameter(Mandatory=$true)]
        [string]
        $StorageAccountName,

        [Parameter()]
        [int]
        $Last,

        [Parameter()]
        [string]
        $Path = "$env:TEMP\azfw_report.htm",

        [Parameter()]
        [switch]
        $Console

    )

    $ErrorActionPreference = 'Stop'

    $LOG_CONTAINER_NAME = 'insights-logs-azurefirewall'

    # Check module availability
    Get-ModuleCompatability -Last $Last -Console $Console

    Write-Output "Loading logs storage account ..."

    $sa_obj = Get-AzStorageAccount | ?{$_.StorageAccountName -eq $StorageAccountName}
    $sa_context = $sa_obj.Context
    $sa_key = ($sa_obj | Get-AzStorageAccountKey)[0].Value 

    $blob_timestamp_selection = @{
        n = 'LogTime'
        e = {
            $_.Name -match '\/PROVIDERS\/MICROSOFT\.NETWORK\/AZUREFIREWALLS\/\S+?\/y=(\d{4})\/m=(\d{2})\/d=(\d{2})\/h=(\d{2})\/m=(\d{2})\/PT1H\.json$' > $null
            Return [datetime]"$($Matches[1])-$($Matches[2])-$($Matches[3]) $($Matches[4]):$($Matches[5])"
        }
    }

    # Listing log blobs

    Write-Output "Finding log blobs ..."

    $all_blobs = Get-StorageAccountBlobsAPI -StorageAccountName $sa_obj.StorageAccountName -Container $LOG_CONTAINER_NAME -StorageKey $sa_key
    If ($Last) {
        $target_blobs = $all_blobs | Select $blob_timestamp_selection, LastModified, Name | Sort-Object LogTime -Descending | Select -First $Last
    } Else {
        If ($Console) {
            $target_blobs = $all_blobs | Select $blob_timestamp_selection, LastModified, Name | Sort-Object LogTime -Descending | Out-ConsoleGridView -PassThru
        } Else {
            $target_blobs = $all_blobs | Select $blob_timestamp_selection, LastModified, Name | Sort-Object LogTime -Descending | Out-GridView -PassThru
        }        
    }

    $output = @{
        applog_data = [string[]]@()
        netlog_data = [string[]]@()
    }

    ForEach ($blob in $target_blobs) {

        # Download blob
        Write-Host "Downloading blob: $($blob.Name) ..."

        $azfw_log = Get-StorageAccountBlobContentAPI -StorageAccountName $sa_obj.StorageAccountName -Container $LOG_CONTAINER_NAME -BlobName $blob.Name -StorageKey $sa_key
    
        # Parse
        Write-Host "Parsing blob: $($blob.Name) ..."
        Parse-AZFWLog -AZFWLog ([ref]$azfw_log) -Output $output
        
    }

    # Init file stream

    If (Test-Path $Path) {Remove-Item $Path}
    $file_stream = New-Object System.IO.StreamWriter $Path

    # Write report file using template

    $report = Get-Content "$PSScriptRoot\template\azfw_report_template.htm"

    ForEach ($line in $report) {
        $line = [regex]::Replace($line,'{{ ([^\s]*) }}', { param($match) Return ($output."$($match.Groups[1].Value)" -join "`n") } )
        $file_stream.Write($line)
        $file_stream.Write("`n")
    }

    $file_stream.Close()

    & $Path

}

Export-ModuleMember -Function New-NSGLogReport
Export-ModuleMember -Function New-AZFWLogReport