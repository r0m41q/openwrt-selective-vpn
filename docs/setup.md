# Set up over SSH

Install the package first, then run `xcloud-bypass setup` as root. The wizard can import a local OpenVPN profile or use an enabled OpenVPN client already configured on the router. It asks for the LAN scope, devices, and console or browser routing separately. Leave the device field empty to include eligible LAN devices.

The wizard shows the routing scope before applying it. It uses your SSH client address to check that the router's return route stays available. If the session cannot provide an IPv4 client address, enter one when asked. The wizard prints the router URL it discovers for that route.

After applying, check that SSH and the router UI still work, then confirm in the wizard or run `xcloud-bypass confirm` from another SSH session. An unconfirmed change rolls back after two minutes. Use `xcloud-bypass status` or `xcloud-bypass doctor` for redacted JSON diagnostics. `xcloud-bypass uninstall` removes the application's owned configuration; it does not remove the package or unrelated VPN clients.
