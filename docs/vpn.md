In LuCI, open the application's VPN page under **Services**.

Import a TUN client profile with inline certificates and keys, or select an
existing OVPN client. Profiles are limited to 32 KiB. Scripts, plugins,
external key files and insecure TLS options are rejected. Imported routes and
DNS settings are filtered to keep normal traffic on WAN.

If the profile needs a username and password, enter both and save them. Saved
credentials are never displayed. Uploading a replacement creates a new profile;
the active VPN keeps using the previous profile until you apply routing settings.
The selection is kept in this browser tab until you apply routing settings.

Use **Reconnect active VPN** after changing the active managed client's
credentials. Enter the IPv4 address of the device you are using to manage the
router, then confirm the connection before the recovery window expires. Manage
external clients through their existing OVPN configuration.

Tunnel readiness does not establish that a selected connection uses the VPN. Check the packet path separately.

## Using an existing client

Selecting an existing client lists everything that keeps it from working as it is, such as a missing `route-nopull`, a `redirect-gateway` line or a plain `dev tun`. You can fix those in its configuration, or click **Copy into a managed profile**.

Copying builds a profile from the client's `.ovpn` file, or from its LuCI options when it has no file. Certificate and key files it points to are copied inline, and a username and password file is copied when it is root-owned and holds just the two lines. The copy then gets the same checks and filtering as an upload. Your client is not changed.

When routing with the copied profile is applied, the old client is stopped and disabled, so only one connection to your provider is open. Disable or uninstall turns it back on and starts it again, unless you changed its enabled setting in the meantime.
