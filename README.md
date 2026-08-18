# crowdsec-unifi-bouncer

A small, self-authored [CrowdSec](https://www.crowdsec.net/) bouncer that syncs
CrowdSec's local decisions to a UniFi (UDM Pro) firewall address group, blocking banned
IPs at the router edge instead of only at individual reverse-proxied services.

Built after evaluating two existing third-party bouncers (`Teifun2/cs-unifi-bouncer`,
`developingchet/cs-unifi-bouncer-pro`) and finding neither a clean fit — one caused a
real CPU-exhaustion incident on a previous deployment (traced to UniFi firewall-policy
*reordering* on every decision change), the other has no external validation. This
bouncer takes the good design ideas from both (official-SDK-style streaming, a
membership-only update model that never touches policy order) without either project's
downsides.

Published to Docker Hub as `nipar44/crowdsec-unifi-bouncer` (`latest` + explicit
`vX.Y.Z` tags read from the Dockerfile's own `org.opencontainers.image.version` label).

## This repo vs. the homelab deployment

This repo owns the **code and the build** (source, Dockerfile, CI publish pipeline).
It does not document how to actually deploy/run it, the required UniFi/CrowdSec
credentials, the one-time UniFi firewall policy setup, or the break-glass access path —
that's homelab-specific and lives in a separate, private repo
(`infrastructure/crowdsec-unifi-bouncer/README.md`), the same split
[nipar4/predbat_addon](https://github.com/nipar4/predbat_addon) uses for its own addon
consumers.

## Build

`.github/workflows/build.yml` builds and pushes on every push to `main` that touches
the Dockerfile, `requirements.txt`, or the script itself — `docker/setup-buildx-action`
+ `docker/build-push-action` on GitHub-hosted runners, no self-hosted infrastructure
needed.

## Security notes

- No credentials are ever hardcoded — the UniFi API key and CrowdSec bouncer key are
  read from environment variables / Docker secrets at runtime, set by whatever deploys
  this image.
- Final image is Google's distroless Python base (no shell, no package manager,
  nonroot) — see the Dockerfile's own comments for why.
- Defense-in-depth: refuses to ever add a Cloudflare IP range to the block list,
  regardless of what CrowdSec reports.

## License

MIT — see `LICENSE`.
