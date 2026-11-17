# Routing

In LuCI, open **Services → Selective VPN → Routing** after choosing a VPN.

The page is a list of rules. **Global** comes first and applies to every eligible LAN device that has no rule of its own. A fresh install has only an empty Global rule, so nothing is routed yet.

To give one device different routes, add it from the DHCP list or enter its IPv4 address. A new device rule starts with a copy of Global's routes. The device then uses only its own rule, never Global. Clear its presets and destinations to keep that device on its normal connection. Use a reserved DHCP address so the device keeps its IP.

Each rule can have:

- **Presets**: ready-made destination sets, see [presets](presets.md). Each preset keeps its own protocol and port.
- **Custom destinations**: domains, IPv4 addresses and aligned IPv4 subnets.
- **Protocols** and **destination ports** for the custom destinations. Leave ports blank for all ports.

Enter the IPv4 address of the device you are using, acknowledge the limits, and click **Preview changes**. This saves the rules as a draft and shows the exact routes per rule: which devices, which destinations and which traffic. Nothing changes on the network until you apply. Confirm router access within two minutes after applying, or the change rolls back.

## Importing hand-made PBR policies

If you already send traffic through the VPN with your own PBR policies, they are listed under **Other PBR policies**, with whether each one can become a rule. A policy can be imported when it is enabled, uses the selected VPN's network interface (for a copied client, the old client's interface), and matches either everyone or one device IPv4 address, with domains, IPv4 addresses or subnets as destinations and TCP, UDP or all protocols. All protocols become TCP and UDP. Anything else, such as MAC or subnet sources, source ports or DNS policies, stays as it is.

**Import policies** adds them to the draft rules: a policy for everyone goes into Global, a policy for one device into that device's rule, which is created when missing. Destinations that match a preset become that preset. Policies for one device that use different protocols or ports than its rule are left out. Devices with their own rule do not get the routes imported into Global, and the page says which ones.

Policies without a section name are given one, based on their name, so they can be tracked. PBR ignores section names, so this changes nothing on the network.

Nothing changes on the network until you apply. Applying removes the imported policies from PBR. Removing the rule that replaced one, disabling routing or uninstalling puts it back, unless you created another policy with the same section name. Restored policies are added after your other PBR policies.

## Limits

- Only IPv4 is routed. IPv6 connections to the same services leave through your normal connection.
- Domain rules work through the router's dnsmasq. Devices must use the router for DNS. Encrypted DNS in a browser or device, and cached answers, can skip this.
- Destination IPs can be shared with unrelated services, so their traffic goes through the VPN as well.
- Other PBR policies keep their priority. The preview warns when one may overlap.
- A working tunnel and a matching rule do not prove a connection used the VPN. See [diagnostics](diagnostics.md).
