# crowdsec-unifi-bouncer

A small, self-authored [CrowdSec](https://www.crowdsec.net/) bouncer that syncs
CrowdSec's local decisions to a UniFi (UDM Pro) firewall address group, blocking banned
IPs at the router edge instead of only at individual reverse-proxied services.

Deliberately narrow in scope — see "How this differs" below for the design principle
that shapes everything else in this README.

Published to Docker Hub as [`nipar44/crowdsec-unifi-bouncer`](https://hub.docker.com/r/nipar44/crowdsec-unifi-bouncer)
(`latest` + explicit `vX.Y.Z` tags read from the Dockerfile's own
`org.opencontainers.image.version` label).

## How this differs

A common approach to this kind of bouncer manages UniFi firewall *policies* directly —
creating, updating, or reordering the policy that actually enforces the block whenever
the ban list changes. Reordering a policy set is a genuinely expensive operation on UDM
Pro hardware (the router has to recompute and reload its ruleset), and doing it on
nearly every change is a real, documented way to sustain high CPU load on the
controller.

This bouncer takes a structurally narrower approach: it never creates, edits, or
reorders a firewall *policy*, not even once, not even at startup — only ever
reads/writes firewall *group* membership, which is cheap regardless of how often it
changes. The one-time policy setup covered below (including its own one-time reorder
step, done by hand) is deliberately the only place a policy ever gets touched — never
repeated by this code, for as long as it runs.

## Before you install: read this

**This bouncer only ever manages UniFi firewall *group* membership. It never creates,
edits, or reorders a firewall *policy*.** A group is just a named list of IP
addresses — it blocks nothing by itself. A policy is the actual rule that says "traffic
matching this group gets dropped." Without a policy referencing a group, the bouncer
will run, sync CrowdSec's decisions, log `Synced firewall group -> N members`, and
appear to work perfectly — while doing **nothing** to real traffic.

Creating that policy is a genuine one-time manual step, covered in full below, and it
has a second, easy-to-miss requirement: **the policy must also be explicitly reordered
ahead of UniFi's predefined rules, or it will never actually be evaluated even though it
exists correctly.** This isn't theoretical — it's exactly what happened on the reference
deployment for its first ~30 hours in production: the policy was created correctly,
looked correct, held the right group, and simply never fired, because a predefined
"Allow" rule for the same zone pair matched every request first. The policy's own
numeric `index` field looked like it controlled order; it doesn't. A separate reorder
call does. Don't skip step 4 below.

## Installation

### Prerequisites

- A running CrowdSec instance with LAPI access (this bouncer talks to
  `/v1/decisions/stream`, the same interface every official CrowdSec bouncer uses).
- A UniFi controller running the modern zone-based firewall (UDM Pro or equivalent,
  UniFi OS / Network app).
- Docker (or Docker Swarm) to run the image.

### 1. Register a CrowdSec bouncer

On your CrowdSec instance:

```bash
cscli bouncers add unifi-bouncer
```

This prints an API key — save it to a file, e.g. `./secrets/crowdsec_bouncer_key`.

### 2. Get a UniFi API key

Generate one from the UniFi controller's own settings (Settings → Admins → your
account → API key, or the equivalent for your controller version). Save it to a file,
e.g. `./secrets/unifi_api_key`. This key needs admin-level access on the classic REST
API today — see "Known limitations" below.

### 3. Run the container

```yaml
services:
  crowdsec-unifi-bouncer:
    image: nipar44/crowdsec-unifi-bouncer:latest
    restart: unless-stopped
    environment:
      - CROWDSEC_LAPI_URL=http://crowdsec:8080
      - CROWDSEC_BOUNCER_API_KEY_FILE=/run/secrets/crowdsec_bouncer_key
      - UNIFI_HOST=https://192.168.1.1          # your UniFi controller
      - UNIFI_API_KEY_FILE=/run/secrets/unifi_api_key
      - UNIFI_SITE=default
      - UNIFI_GROUP_NAME=crowdsec-banned-ips
      - DRY_RUN=true                             # start here -- see step 4
      - POLL_INTERVAL_SECONDS=5
    volumes:
      - ./secrets/crowdsec_bouncer_key:/run/secrets/crowdsec_bouncer_key:ro
      - ./secrets/unifi_api_key:/run/secrets/unifi_api_key:ro
    ports:
      - "9105:9105"                              # Prometheus metrics, optional
```

**Start with `DRY_RUN=true`.** In this mode the bouncer connects, reconciles, and logs
exactly what it *would* do — including what it would name/create groups as — without
writing anything to UniFi. Confirm the logs look sane (real decision counts, no
connection errors) before going further.

Full environment variable reference:

| Variable | Default | Purpose |
|---|---|---|
| `CROWDSEC_LAPI_URL` | `http://crowdsec:8080` | CrowdSec LAPI base URL |
| `CROWDSEC_BOUNCER_API_KEY_FILE` | *(required)* | Path to the bouncer key from step 1 |
| `CROWDSEC_ORIGINS` | `crowdsec` | Comma-separated decision origins to act on. The default excludes CrowdSec's shared community blocklists (`lists`/`CAPI`) — those can be tens of thousands of entries, not something a UniFi firewall group should hold |
| `UNIFI_HOST` | *(required)* | Your UniFi controller's URL, e.g. `https://192.168.1.1` |
| `UNIFI_API_KEY_FILE` | *(required)* | Path to the UniFi API key from step 2 |
| `UNIFI_SITE` | `default` | UniFi site name |
| `UNIFI_GROUP_NAME` | `crowdsec-banned-ips` | Name of the IPv4 firewall group this bouncer creates/manages |
| `UNIFI_GROUP_NAME_V6` | *(unset)* | Optional — name of a second, independent IPv6 firewall group (`ipv6-address-group`). Empty/unset disables IPv6 support entirely: IPv6 decisions are skipped, not attempted against a group that doesn't exist. Set this to enable it — see step 4 for the one-time policy setup this also needs |
| `UNIFI_VERIFY_TLS` | `false` | UDM Pro's default cert is self-signed |
| `UNIFI_POLICY_ID` | *(unset)* | Optional — once you've created the IPv4 policy (step 4), set its `_id` here to get a `crowdsec_unifi_bouncer_policy_hits` metric, the one signal that proves real enforcement, not just group membership |
| `UNIFI_POLICY_ID_V6` | *(unset)* | Same as `UNIFI_POLICY_ID`, for the IPv6 policy — exposed as `crowdsec_unifi_bouncer_policy_hits_v6` |
| `UNIFI_CLOUDFLARE_GROUP_NAME` | *(unset)* | Optional, unrelated to ban blocking — keeps a separate, already-existing UniFi group in sync with Cloudflare's published IP ranges, for WAN-restriction policies. Leave unset unless you specifically want this |
| `DRY_RUN` | `true` | Set `false` only after step 4 below is complete |
| `POLL_INTERVAL_SECONDS` | `2` | How often to check CrowdSec for new/expired decisions |
| `API_WRITE_DELAY_SECONDS` | `1.0` | Throttle before any UniFi write |
| `RECONCILE_INTERVAL_SECONDS` | `21600` (6h) | Full resync interval, self-healing against any missed incremental update |
| `METRICS_PORT` | `9105` | Prometheus `/metrics` endpoint |

### 4. Create the UniFi policy (or policies) — the step that actually enables blocking

Repeat this whole section once for IPv4 (`UNIFI_GROUP_NAME`) and, if you've set
`UNIFI_GROUP_NAME_V6`, a second time for IPv6 — they're two entirely independent
group/policy pairs.

**4a. Let the group get created for real.** Flip `DRY_RUN=false` and restart the
container. On first run it will create the group(s) for real (if they don't already
exist) and log their IDs:

```
Created IPv4 firewall group 'crowdsec-banned-ips' (id=<the real group id>)
Created IPv6 firewall group 'crowdsec-banned-ips-v6' (id=<the real group id>)
```

Copy the ID(s). The group is still empty of consequence at this point — it has no
policy referencing it, so nothing is blocked yet. That's expected.

**4b. Create the policy**, referencing the group's real ID. This needs the v2
zone-based-firewall API — not documented in UniFi's own public docs at all, determined
through direct testing against a real controller. Find your zone IDs first via
`GET .../v2/api/site/<site>/firewall-zones` if you don't already know them:

```bash
curl -k -X POST "https://<unifi-host>/proxy/network/v2/api/site/<site>/firewall-policies" \
  -H "X-API-KEY: <your unifi api key>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "BLOCK",
    "enabled": true,
    "name": "Block CrowdSec-banned IPs",
    "protocol": "all",
    "ip_version": "BOTH",
    "create_allow_respond": false,
    "connection_state_type": "ALL",
    "schedule": { "mode": "ALWAYS" },
    "source": {
      "zone_id": "<your WAN/External zone id>",
      "matching_target": "IP",
      "matching_target_type": "OBJECT",
      "ip_group_id": "<the group id from 4a>"
    },
    "destination": {
      "zone_id": "<your LAN/Internal zone id>",
      "matching_target": "ANY"
    }
  }'
```

Note the zone IDs are nested inside `source`/`destination` as `zone_id`, not top-level
fields — confirmed by reading back a real, working policy's exact stored shape. **Do
not** set `create_allow_respond: true` on a `BLOCK` policy — that field is meant for
`ALLOW` policies (it auto-creates a companion return-traffic rule) and UniFi will
reject a `BLOCK` policy that has it
(`api.err.FirewallPolicyCreateRespondTrafficPolicyNotAllowed`).

The response includes the new policy's own `_id` — save it too, for step 4c and for
`UNIFI_POLICY_ID`/`UNIFI_POLICY_ID_V6` above.

**4c. Reorder the policy ahead of UniFi's predefined rules. This step is required, not
optional** — see the warning at the top of this README for why. This is a *different*
endpoint with its own top-level shape (unlike 4b above, these zone IDs are NOT nested):

```bash
curl -k -X PUT "https://<unifi-host>/proxy/network/v2/api/site/<site>/firewall-policies/batch-reorder" \
  -H "X-API-KEY: <your unifi api key>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_zone_id": "<your WAN/External zone id>",
    "destination_zone_id": "<your LAN/Internal zone id>",
    "before_predefined_ids": ["<the policy id from 4b>"]
  }'
```

### 5. Verify it's actually working

Group membership syncing correctly is not proof a policy is enforcing anything — the
reference deployment's own IPv4 policy sat at 0 hits for hours even while the group was
correctly populated, simply because no banned IP had retried yet in that window. Two
real checks, per policy:

- `GET .../v2/api/site/<site>/firewall-policies/<policy id>` — its `hits` field
  (absent entirely until the first match, not present as `0`) increments only on a real
  match. If you have other policies on the same zone pair with real traffic, watching
  *their* hit counts grow confirms the zone pair itself is being evaluated at all, which
  helps distinguish "no banned IP has retried yet" from "the policy isn't wired up."
- If `UNIFI_POLICY_ID`/`UNIFI_POLICY_ID_V6` is set, the bouncer exposes this as
  `crowdsec_unifi_bouncer_policy_hits`/`_v6` on its own metrics endpoint — the single
  metric that proves real router-level enforcement, not just group membership.

## Known limitations

- **Single UniFi site.** `UNIFI_SITE` is one value; multi-site controllers aren't
  supported.
- **No automated test suite.** This is validated by live testing against a real
  controller and a local test harness with stubbed dependencies, not a full mocked
  unit-test suite shipped with the repo.
- **The UniFi API key needs broad access.** There's no confirmed way to scope a UniFi
  API credential down to firewall-group-only access on the classic REST API — this
  bouncer likely holds more access than it strictly needs.
- **Range-scoped Cloudflare exclusion.** The Cloudflare-safety-check (never block a
  Cloudflare-owned address) only checks plain IPs, not CIDR-range-scoped decisions —
  every decision observed against the reference deployment so far has been IP-scoped,
  not range-scoped.

## Security notes

- No credentials are ever hardcoded — the UniFi API key and CrowdSec bouncer key are
  read from environment variables / Docker secrets at runtime, set by whatever deploys
  this image.
- Final image is Google's distroless Python base (no shell, no package manager,
  nonroot) — see the Dockerfile's own comments for why.
- Defense-in-depth: refuses to ever add a Cloudflare IP range to the block list,
  regardless of what CrowdSec reports (checked against Cloudflare's own published
  ranges, both IPv4 and IPv6).

## This repo vs. a specific deployment

This repo owns the code, the build, and — as of this README — generic installation
instructions. It does not cover any *specific* homelab's deployment details (exact
paths, Swarm vs. plain Compose, backup/monitoring integration) — those are inherently
environment-specific and out of scope here.

## Build

`.github/workflows/build.yml` builds and pushes on every push to `main` that touches
the Dockerfile, `requirements.txt`, or the script itself — `docker/setup-buildx-action`
+ `docker/build-push-action` on GitHub-hosted runners, no self-hosted infrastructure
needed.

## License

MIT — see `LICENSE`.
