New-LabDefinition -Name Lab2 -DefaultVirtualizationEngine Azure

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:DomainName' = 'contoso.com'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Memory' = 2GB
}

Add-LabVirtualNetworkDefinition -Name Servers  -AddressSpace 192.168.100.0/24
Add-LabVirtualNetworkDefinition -Name Clients1 -AddressSpace 192.168.200.0/24 -AzureProperties @{ DnsServers = '192.168.100.10' }
Add-LabVirtualNetworkDefinition -Name Clients2 -AddressSpace 192.168.210.0/24 -AzureProperties @{ DnsServers = '192.168.100.10' }

Add-LabMachineDefinition -Name DC1 -Roles RootDC -Network Servers -IpAddress 192.168.100.10

Add-LabMachineDefinition -Name Client1 -Network Clients1 -IpAddress 192.168.200.10
Add-LabMachineDefinition -Name Client2 -Network Clients2 -IpAddress 192.168.210.10

Install-Lab

Show-LabDeploymentSummary -Detailed
