In LuCI, **Services → Selective VPN → Routing** after choosing a VPN.

The default scope covers eligible devices in the LAN firewall zone. To limit it,
choose **Selected devices** and enter IPv4 addresses or DHCP hostnames. An empty
device list is rejected. DHCP suggestions add addresses only when you choose them.
Use reserved addresses if a device's DHCP address may change.

The current build starts with its console service destinations selected and its
browser service destinations unselected. Custom domains, IPv4 addresses and
subnets are also supported. The advanced static console fallback uses two
addresses observed on one setup, which may become outdated.

Enter your management device's IPv4 address, acknowledge the limitations, and
preview. Check the resolved sources, destinations and warnings before applying.
If router configuration changes, preview again. Confirm router access within the
remaining recovery window; otherwise the change rolls back automatically.

Domain matching needs router DNS with dnsmasq nftset support. Encrypted DNS,
cached answers and IPv6 can bypass these IPv4 policies. Tunnel and policy checks
do not verify destination access.
