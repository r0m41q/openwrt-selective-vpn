**Services → Selective VPN → Overview** for tunnel, PBR, DNS and routing
status. Updates run at most once every 30 seconds after the previous update
finishes, pause in hidden tabs, and stop on failure. Reports older than a minute
are marked stale. Diagnostics run only when requested.

The overview shows saved policy sources and destinations alongside evidence
from the running router. A populated DNS set or a packet counter does not prove
traffic left through the VPN. Exit IP and destination access are not checked.

Recovery controls use saved settings. **Reload PBR** reapplies those settings and
reloads the shared service. **Restart managed VPN** affects the managed client;
external clients keep their own controls. Disable keeps saved selections and
profiles. Restore needs an earlier confirmed configuration.

Enter your management device's IPv4 address before a recovery action, then
confirm router access within the recovery window. A lost response is not retried.
Refresh status before another action. If recovery remains stuck, use
`selective-vpn doctor` over SSH and keep the recovery service running.

On **Diagnostics**, run checks and download the redacted JSON report. It contains
fixed status fields, counters and recent log category counts. It excludes
addresses, domains, credentials and raw logs. Log counts include all OpenVPN
clients and can describe earlier failures.

To validate routing, compare counters before and after traffic to a selected
destination, with router DNS in use and client DNS caches cleared. Inspect the
matching flow on both WAN and VPN interfaces. Separately check a device outside
the selected scope and ordinary traffic. IPv6 and encrypted DNS need separate
checks.
