In LuCI, **Services → XCloud Gaming → VPN**.

Import a TUN client profile with inline certificates and keys, or select an
existing OVPN client. Profiles are limited to 32 KiB. Scripts, plugins,
external key files and insecure TLS options are rejected. Imported routes and
DNS settings are filtered to keep normal traffic on WAN.

If the profile needs a username and password, enter both and save them. Saved
credentials are never displayed. Uploading a replacement creates a new profile;
the active VPN keeps using the previous profile until you apply routing settings.
The selection is kept in this browser tab for that next change.

Use **Reconnect active VPN** after changing the active managed client's
credentials. Enter the IPv4 address of the device you are using to manage the
router, then confirm the connection before the recovery window expires. Manage
external clients through their existing OVPN configuration.

Tunnel readiness does not establish successful Xbox sign-in or gameplay.
