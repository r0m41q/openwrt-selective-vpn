# Routing

In LuCI, open **Services → Selective VPN → Routing** after choosing a VPN.

The page is a list of rules. **Global** comes first and applies to every eligible LAN device that has no rule of its own. A fresh install has only an empty Global rule, so nothing is routed yet.

To give one device different routes, add it from the DHCP list or enter its IPv4 address. A new device rule starts with a copy of Global's routes. The device then uses only its own rule, never Global. Clear its presets and destinations to keep that device on its normal connection. Use a reserved DHCP address so the device keeps its IP.

Each rule can have:

- **Presets**: ready-made destination sets, see [presets](presets.md). Each preset keeps its own protocol and port.
- **Custom destinations**: domains, IPv4 addresses and aligned IPv4 subnets.
- **Protocols** and **destination ports** for the custom destinations. Leave ports blank for all ports.

Enter the IPv4 address of the device you are using, acknowledge the limits, and click **Preview changes**. This saves the rules as a draft and shows the exact routes per rule: which devices, which destinations and which traffic. Nothing changes on the network until you apply. Confirm router access within two minutes after applying, or the change rolls back.

## Limits

- Only IPv4 is routed. IPv6 connections to the same services leave through your normal connection.
- Domain rules work through the router's dnsmasq. Devices must use the router for DNS. Encrypted DNS in a browser or device, and cached answers, can skip this.
- Destination IPs can be shared with unrelated services, so their traffic goes through the VPN as well.
- Other PBR policies keep their priority. The preview warns when one may overlap.
- A working tunnel and a matching rule do not prove a connection used the VPN. See [diagnostics](diagnostics.md).
