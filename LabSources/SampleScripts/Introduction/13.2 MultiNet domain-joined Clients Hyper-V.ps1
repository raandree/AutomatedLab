New-LabDefinition -Name Lab1 -DefaultVirtualizationEngine HyperV

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:DomainName'      = 'contoso.com'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Memory'          = 2GB
}

Add-LabVirtualNetworkDefinition -Name Servers  -AddressSpace 192.168.100.0/24
Add-LabVirtualNetworkDefinition -Name Clients1 -AddressSpace 192.168.200.0/24
Add-LabVirtualNetworkDefinition -Name Clients2 -AddressSpace 192.168.210.0/24

Add-LabMachineDefinition -Name DC1 -Roles RootDC -Network Servers -IpAddress 192.168.100.10 -DnsServer1 192.168.100.10 -Gateway 192.168.100.1

$networkAdapters = @()
$networkAdapters += New-LabNetworkAdapterDefinition -VirtualSwitch Servers -Ipv4Address 192.168.100.1 -Ipv4DNSServers 192.168.100.10
$networkAdapters += New-LabNetworkAdapterDefinition -VirtualSwitch Clients1 -Ipv4Address 192.168.200.1
$networkAdapters += New-LabNetworkAdapterDefinition -VirtualSwitch Clients2 -Ipv4Address 192.168.210.1
Add-LabMachineDefinition -Name Router -Roles Routing -NetworkAdapter $networkAdapters

Add-LabMachineDefinition -Name Client1 -Network Clients1 -IpAddress 192.168.200.10 -DnsServer1 192.168.100.10 -Gateway 192.168.200.1
Add-LabMachineDefinition -Name Client2 -Network Clients2 -IpAddress 192.168.210.10 -DnsServer1 192.168.100.10 -Gateway 192.168.210.1

Install-Lab

Show-LabDeploymentSummary -Detailed
