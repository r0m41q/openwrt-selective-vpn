# Presets

Presets are fixed destination sets shipped with the package. Tick one on a rule to route it. Removing a preset leaves the rule's custom destinations alone. Each preset becomes its own PBR policy with its own protocol and port.

| Preset | Traffic | Destinations |
| --- | --- | --- |
| xCloud native | TCP 443 | `xsts.auth.xboxlive.com`, `xgpuconsole.gssv-play-prod.xboxlive.com` |
| xCloud web | TCP 443 | `xgpuweb.gssv-play-prod.xboxlive.com`, `xgpuwebf2p.gssv-play-prod.xboxlive.com` |
| xCloud native static IPs (experimental) | TCP 443 | `20.201.200.49`, `51.12.31.0` |

The two xCloud presets route sign-in and session setup for the console app and the browser. The static preset holds addresses seen for the native domains on one setup. Use it alone when router DNS is not available, or together with the native preset. Those addresses can change at any time.

Domain presets need devices to use the router for DNS. See [routing](routing.md#limits).
