#!/usr/bin/env python3
"""CrowdSec -> UniFi firewall-group bouncer.

Custom-built 2026-08-13 after evaluating two existing third-party bouncers (see
crowdsec-unifi-bouncer-plan.md at the repo root for the full research and design
history) -- neither was clean enough to just adopt (one was previously deployed here
and abandoned after it consumed all CPU on the UniFi controller; both have real
provenance/validation concerns).

Design deliberately never touches UniFi firewall *policies* -- only ever reads/writes
one firewall *group*'s membership list. The one-time zone-based policy referencing
this group must be created by hand in the UniFi UI (Phase 5 of the plan doc). This is
the key lesson taken from analysing the real source of the tool that caused the prior
CPU-exhaustion incident: it reordered the entire zone-based policy set on nearly every
ban-list change, a known-expensive whole-ruleset operation. Never reordering or
recreating a policy at all -- not even once, not even at startup -- structurally
prevents that class of bug from ever being reintroduced here.
"""

import logging
import os
import sys
import time
from ipaddress import ip_address, ip_network

import requests
from prometheus_client import Counter, Gauge, start_http_server

CROWDSEC_LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
CROWDSEC_BOUNCER_API_KEY_FILE = os.environ["CROWDSEC_BOUNCER_API_KEY_FILE"]
# Only block decisions this instance detected itself by default -- NOT CrowdSec's
# shared community blocklists (origin "lists"/"CAPI"). Found live 2026-08-13, Phase 4's
# dry-run test: the LAPI decision stream returns ~64,000 decisions total, but all but
# ~10 of them are shared community threat-intel (40k+ "lists", 24k+ "CAPI"), not this
# homelab's own detections. Pushing that volume into a UniFi firewall group would be
# both impractical and a real load risk on its own, regardless of the update-mechanism
# design already avoiding policy reordering. Comma-separated if more than one origin is
# ever deliberately wanted.
CROWDSEC_ORIGINS = set(os.environ.get("CROWDSEC_ORIGINS", "crowdsec").split(","))

UNIFI_HOST = os.environ["UNIFI_HOST"]  # e.g. https://192.168.1.1
UNIFI_API_KEY_FILE = os.environ["UNIFI_API_KEY_FILE"]
UNIFI_SITE = os.environ.get("UNIFI_SITE", "default")
UNIFI_GROUP_NAME = os.environ.get("UNIFI_GROUP_NAME", "crowdsec-banned-ips")
UNIFI_VERIFY_TLS = os.environ.get("UNIFI_VERIFY_TLS", "false").lower() == "true"  # UDM Pro's cert is self-signed by default
# Optional -- the one-time, hand-created zone policy's own _id (Phase 5 of the plan
# doc), used ONLY for a periodic read-only hit-count metric. Does not violate the
# "never touch policies" design principle above -- that's about writes (create/
# reorder/delete), this is a single GET on a known, fixed policy that already exists.
# Unset/empty skips this metric entirely (e.g. before the one-time policy exists yet).
UNIFI_POLICY_ID = os.environ.get("UNIFI_POLICY_ID", "")
# Optional -- name of a UniFi address-group to keep in sync with Cloudflare's real
# published IPv4 ranges (e.g. "cloudflare-ips-v4", the group backing the separate
# WAN-restriction policies added 2026-08-13, see improvement-plan.md's Priority 0
# item). Same safety scope as everything else here: only ever writes this one
# group's *membership*, never touches the policies referencing it. Empty/unset
# disables this entirely -- opt-in, since this manages a group the bouncer didn't
# originally create, unlike its own crowdsec-banned-ips group. Must already exist
# on the controller; this code never creates it (deliberately -- see sync function).
UNIFI_CLOUDFLARE_GROUP_NAME = os.environ.get("UNIFI_CLOUDFLARE_GROUP_NAME", "")

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
# 2026-08-27: lowered from 60s. Researched whether CrowdSec's official Go bouncer SDK
# (csbouncer.StreamBouncer, the thing "real streaming" in the roadmap referred to)
# does genuine server-push -- it doesn't. It's the identical /v1/decisions/stream HTTP
# poll this file already does, on a configurable TickerInterval that itself defaults
# to 60s (confirmed against go-cs-bouncer's own docs). There is no push/SSE/WebSocket
# transport for local decisions in the open-source LAPI -- "streaming" is just this
# poll-loop's name. So the only real lever is a shorter interval, which is free here:
# UniFi is still only ever written to when the ban set actually changed (pending_write
# gate, unchanged) -- polling more often does not multiply UniFi writes in normal
# operation, only how quickly a real change gets noticed and pushed.
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "2"))
API_WRITE_DELAY_SECONDS = float(os.environ.get("API_WRITE_DELAY_SECONDS", "1.0"))
# How often to redo a *full* reconciliation (fetch CrowdSec's complete current decision
# list and recompute the desired ban set from scratch) rather than relying solely on
# the ongoing loop's incremental new/deleted deltas. Added 2026-08-13 after fixing a
# real gap: full reconciliation previously only happened once, at process startup --
# between restarts, correctness depended entirely on the incremental `deleted` stream
# reliably reporting every removal, including natural TTL expiry (not just explicit
# `cscli` deletions), which was never actually verified. This is the self-healing
# safety net regardless of whether that assumption holds. 6h default -- frequent enough
# to catch drift in normal operation, infrequent enough to stay clearly cheap.
RECONCILE_INTERVAL_SECONDS = int(os.environ.get("RECONCILE_INTERVAL_SECONDS", str(6 * 3600)))

CLOUDFLARE_IPV4_URL = os.environ.get("CLOUDFLARE_IPV4_URL", "https://www.cloudflare.com/ips-v4")
CLOUDFLARE_IPV6_URL = os.environ.get("CLOUDFLARE_IPV6_URL", "https://www.cloudflare.com/ips-v6")
CLOUDFLARE_REFRESH_SECONDS = int(os.environ.get("CLOUDFLARE_REFRESH_SECONDS", str(24 * 3600)))

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9105"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
log = logging.getLogger("crowdsec-unifi-bouncer")

# Scoped to what this bouncer actually needs to answer "is it working, and did the
# last change take effect" from Grafana -- not cs-unifi-bouncer-pro's full metric
# surface (per-scenario labels, shard counts, etc.), matching this build's overall
# "small, fully-understood" scope decision (see crowdsec-unifi-bouncer-plan.md).
METRIC_DECISIONS_TOTAL = Counter(
    "crowdsec_unifi_bouncer_decisions_total", "CrowdSec decisions actually acted on", ["result"])
METRIC_DECISIONS_SKIPPED_TOTAL = Counter(
    "crowdsec_unifi_bouncer_decisions_skipped_total", "CrowdSec decisions filtered out", ["reason"])
METRIC_BANNED_ADDRESSES = Gauge(
    "crowdsec_unifi_bouncer_banned_addresses", "Current size of the UniFi block group")
METRIC_UNIFI_WRITE_TOTAL = Counter(
    "crowdsec_unifi_bouncer_unifi_write_total", "UniFi group-membership write attempts", ["result"])
METRIC_LAST_SYNC_TIMESTAMP = Gauge(
    "crowdsec_unifi_bouncer_last_sync_timestamp_seconds", "Unix time of the last successful CrowdSec poll")
METRIC_LAST_WRITE_TIMESTAMP = Gauge(
    "crowdsec_unifi_bouncer_last_write_timestamp_seconds", "Unix time of the last successful UniFi group write")
METRIC_DRY_RUN = Gauge(
    "crowdsec_unifi_bouncer_dry_run", "1 if running in dry-run mode (no real writes), else 0")
METRIC_CLOUDFLARE_RANGES = Gauge(
    "crowdsec_unifi_bouncer_cloudflare_ranges", "Number of cached Cloudflare IP ranges")
METRIC_POLICY_HITS = Gauge(
    "crowdsec_unifi_bouncer_policy_hits",
    "Cumulative match count on the enforcement policy (real router-level enforcement evidence, not just group membership) -- only set if UNIFI_POLICY_ID is configured")
METRIC_CLOUDFLARE_GROUP_SYNC_TOTAL = Counter(
    "crowdsec_unifi_bouncer_cloudflare_group_sync_total",
    "UniFi Cloudflare-IP-group write attempts -- only used if UNIFI_CLOUDFLARE_GROUP_NAME is configured", ["result"])


def read_secret(path):
    with open(path) as f:
        return f.read().strip()


class CloudflareAllowlist:
    """Fetches and caches Cloudflare's real IP ranges. Never let a CrowdSec decision
    against a Cloudflare-owned address reach the block list, regardless of what
    CrowdSec reports -- defense-in-depth against a header-trust misconfiguration ever
    causing this bouncer to block Cloudflare's own infrastructure.
    """

    def __init__(self):
        self._networks = []
        self._last_refresh = 0.0

    def refresh(self, force=False):
        # Returns True only if a real fetch happened (so callers -- e.g. the UniFi
        # group sync below -- can skip redundant work on the many cycles this is a
        # cheap no-op).
        if not force and (time.time() - self._last_refresh) < CLOUDFLARE_REFRESH_SECONDS:
            return False
        nets = []
        for url in (CLOUDFLARE_IPV4_URL, CLOUDFLARE_IPV6_URL):
            try:
                resp = requests.get(url, timeout=15)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        nets.append(ip_network(line))
            except Exception as e:
                log.warning("Failed to refresh Cloudflare ranges from %s: %s -- keeping previous list", url, e)
                if not self._networks:
                    raise  # first-ever fetch failing is fatal; a stale-but-nonempty list is fine to keep running on
        if nets:
            self._networks = nets
            self._last_refresh = time.time()
            METRIC_CLOUDFLARE_RANGES.set(len(nets))
            log.info("Cloudflare allowlist refreshed: %d ranges", len(nets))
            return True
        return False

    def ipv4_cidrs(self):
        return sorted(str(n) for n in self._networks if n.version == 4)

    def contains(self, ip_str):
        try:
            addr = ip_address(ip_str)
        except ValueError:
            # Not a plain IP -- e.g. a CIDR-range-scoped decision. Known v1 limitation:
            # range-scoped decisions bypass this check entirely. Acceptable for now --
            # every decision observed against this homelab so far has been Ip-scoped,
            # not Range-scoped. Revisit if that changes.
            return False
        return any(addr in net for net in self._networks)


class CrowdSecClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["X-Api-Key"] = api_key

    def decisions_stream(self, startup=False):
        params = {"startup": "true"} if startup else {}
        resp = self.session.get(f"{self.base_url}/v1/decisions/stream", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()  # {"new": [...], "deleted": [...]}


class UniFiClient:
    """Confirmed live 2026-08-13 (read-only) against the real controller: a single
    X-API-KEY header works for this classic REST API path, no separate session-cookie
    login flow needed. See crowdsec-unifi-bouncer-plan.md Phase 2 for the full
    verification.
    """

    def __init__(self, host, api_key, site, verify_tls):
        self.host = host.rstrip("/")
        self.site = site
        self.session = requests.Session()
        self.session.headers["X-API-KEY"] = api_key
        self.session.verify = verify_tls

    def _url(self, path):
        return f"{self.host}/proxy/network/api/s/{self.site}/{path}"

    def _url_v2(self, path):
        return f"{self.host}/proxy/network/v2/api/site/{self.site}/{path}"

    def get_policy_hits(self, policy_id):
        # v2 zone-based-firewall API, not the classic REST API the rest of this class
        # uses -- confirmed live 2026-08-13 (see crowdsec-unifi-bouncer-plan.md Phase 5)
        # that a policy's own hit count lives here, and that the field is omitted
        # entirely (not present as 0) on a policy that's never matched anything yet.
        resp = self.session.get(self._url_v2(f"firewall-policies/{policy_id}"), timeout=15)
        resp.raise_for_status()
        return resp.json().get("hits", 0)

    def list_firewall_groups(self):
        resp = self.session.get(self._url("rest/firewallgroup"), timeout=15)
        resp.raise_for_status()
        return resp.json()["data"]

    def find_group(self, name):
        for g in self.list_firewall_groups():
            if g.get("name") == name:
                return g
        return None

    def create_group(self, name):
        # NOTE: not yet live-verified -- the exact required field set/group_type value
        # for this controller's firmware version needs confirming during Phase 4's
        # dry-run (this call is skipped entirely in dry-run mode). Deliberately does
        # not touch anything policy-related.
        body = {"name": name, "group_type": "address-group", "group_members": []}
        resp = self.session.post(self._url("rest/firewallgroup"), json=body, timeout=15)
        resp.raise_for_status()
        return resp.json()["data"][0]

    def update_group_members(self, group, members):
        # NOTE: field name for the group's own ID was not confirmed live (no group
        # existed yet to inspect during Phase 2's read-only check) -- handles either
        # `_id` or `id`, whichever this controller's API actually returns. Confirm and
        # simplify this once Phase 4 shows the real shape.
        group_id = group.get("_id") or group.get("id")
        body = dict(group)
        body["group_members"] = sorted(members)
        resp = self.session.put(self._url(f"rest/firewallgroup/{group_id}"), json=body, timeout=15)
        if not resp.ok:
            log.error("UniFi rejected group update (HTTP %d): %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return resp.json()["data"][0]


def normalize_member(ip_str):
    # Confirmed live 2026-08-13 (Phase 5): UniFi's classic REST API firewallgroup
    # (address-group) rejects /32 CIDR notation for single hosts --
    # api.err.FirewallGroupInvalidArgs, args echoing the rejected "<ip>/32" value.
    # Bare IPs are what it wants for single-host entries; a real range-scoped decision
    # (already containing a non-/32 mask) is passed through as-is.
    if "/" in ip_str:
        prefix = ip_str.rsplit("/", 1)[1]
        addr = ip_address(ip_str.split("/")[0])
        full_mask = "32" if addr.version == 4 else "128"
        return ip_str if prefix != full_mask else ip_str.split("/")[0]
    return ip_str


def is_ipv4(ip_str):
    # UniFi's "address-group" group_type is IPv4-only -- confirmed live 2026-08-13,
    # rejected a bare IPv6 decision with the same api.err.FirewallGroupInvalidArgs.
    # Properly supporting IPv6 needs a second, address-family-specific UniFi group plus
    # a second zone policy referencing it -- out of scope for v1 (flagged as an open
    # question back in Phase 3, confirmed to actually matter here: 1 of 13 real local
    # decisions today was IPv6). Skip v6 decisions for now rather than crash the sync
    # loop on every cycle.
    try:
        return ip_address(ip_str.split("/")[0]).version == 4
    except ValueError:
        return False


def sync_cloudflare_group(unifi, cf_allow):
    # Deliberately never creates the group -- only crowdsec-banned-ips gets that
    # treatment (this bouncer's own group, created lazily on first live run).
    # cloudflare-ips-v4 is a different, hand-created group backing separate
    # WAN-restriction policies (improvement-plan.md's Priority 0 item); if it's
    # missing, that's a real setup problem worth surfacing, not something to
    # silently paper over by creating a differently-configured group under the
    # same name.
    if not UNIFI_CLOUDFLARE_GROUP_NAME:
        return
    desired = set(cf_allow.ipv4_cidrs())
    if not desired:
        log.warning("Cloudflare group sync: no IPv4 ranges cached yet, skipping")
        return
    try:
        group = unifi.find_group(UNIFI_CLOUDFLARE_GROUP_NAME)
    except requests.RequestException as e:
        log.warning("Cloudflare group sync: failed to look up %r: %s", UNIFI_CLOUDFLARE_GROUP_NAME, e)
        return
    if group is None:
        log.warning("Cloudflare group sync: group %r not found on controller -- create it first, this code never will", UNIFI_CLOUDFLARE_GROUP_NAME)
        return
    current = set(group.get("group_members", []))
    if current == desired:
        return
    added = desired - current
    removed = current - desired
    if DRY_RUN:
        log.info("[dry-run] Would sync Cloudflare group %r: +%d -%d ranges (no write performed)",
                  UNIFI_CLOUDFLARE_GROUP_NAME, len(added), len(removed))
        return
    time.sleep(API_WRITE_DELAY_SECONDS)  # same deliberate throttle as every other UniFi write
    try:
        unifi.update_group_members(group, desired)
    except requests.RequestException as e:
        METRIC_CLOUDFLARE_GROUP_SYNC_TOTAL.labels(result="failure").inc()
        log.error("Failed to sync Cloudflare group %r: %s", UNIFI_CLOUDFLARE_GROUP_NAME, e)
        return
    METRIC_CLOUDFLARE_GROUP_SYNC_TOTAL.labels(result="success").inc()
    log.info("Synced Cloudflare group %r: +%d -%d ranges (now %d total)",
              UNIFI_CLOUDFLARE_GROUP_NAME, len(added), len(removed), len(desired))


def update_policy_hits_metric(unifi):
    # Best-effort -- a failure here (e.g. the controller briefly unreachable) shouldn't
    # take down the bouncer's actual job of syncing bans. Silently does nothing if
    # UNIFI_POLICY_ID isn't configured (e.g. before the one-time policy exists yet).
    if not UNIFI_POLICY_ID:
        return
    try:
        METRIC_POLICY_HITS.set(unifi.get_policy_hits(UNIFI_POLICY_ID))
    except requests.RequestException as e:
        log.warning("Failed to fetch policy hit count: %s", e)


def reconcile(cs, unifi, cf_allow, group, label):
    """Fetch CrowdSec's complete current decision list and recompute the desired ban
    set from scratch -- NOT a union with whatever's already in the UniFi group. Used
    both at process startup and periodically (RECONCILE_INTERVAL_SECONDS) so
    correctness never depends solely on the ongoing loop's incremental deltas. Returns
    the (possibly updated) group object and the freshly-computed banned set.
    """
    already_banned = set(group.get("group_members", []))
    banned = set()

    initial = cs.decisions_stream(startup=True)
    METRIC_LAST_SYNC_TIMESTAMP.set(time.time())
    skipped_cf = 0
    skipped_origin = 0
    skipped_v6 = 0
    for d in initial.get("new") or []:
        if d.get("origin") not in CROWDSEC_ORIGINS:
            skipped_origin += 1
            continue
        ip = d["value"]
        if not is_ipv4(ip):
            skipped_v6 += 1
            continue
        if cf_allow.contains(ip):
            skipped_cf += 1
            continue
        member = normalize_member(ip)
        if member not in already_banned:
            log.info("%s: reconciling CrowdSec ban %s (%s, duration %s) into UniFi group",
                      label, ip, d.get("scenario"), d.get("duration"))
        banned.add(member)
    if skipped_origin:
        METRIC_DECISIONS_SKIPPED_TOTAL.labels(reason="origin").inc(skipped_origin)
        log.info("%s: skipped %d decision(s) outside CROWDSEC_ORIGINS=%s (e.g. shared community blocklists)",
                  label, skipped_origin, sorted(CROWDSEC_ORIGINS))
    if skipped_v6:
        METRIC_DECISIONS_SKIPPED_TOTAL.labels(reason="ipv6").inc(skipped_v6)
        log.warning("%s: skipped %d non-IPv4 decision(s) -- IPv6 not yet supported (needs a separate UniFi group), see README", label, skipped_v6)
    if skipped_cf:
        METRIC_DECISIONS_SKIPPED_TOTAL.labels(reason="cloudflare").inc(skipped_cf)
        log.warning("%s: skipped %d decision(s) whose address falls within Cloudflare's own ranges", label, skipped_cf)

    stale = already_banned - banned
    for member in stale:
        # Same explicit-naming principle as additions above -- a removal deserves the
        # same end-to-end traceability as a ban does.
        log.info("%s: removing %s from UniFi group -- no longer an active CrowdSec decision", label, member)

    pending_write = banned != already_banned
    METRIC_BANNED_ADDRESSES.set(len(banned))
    if pending_write:
        if DRY_RUN:
            log.info("[dry-run] Would sync firewall group %r to %d members (no write performed)",
                      UNIFI_GROUP_NAME, len(banned))
        else:
            time.sleep(API_WRITE_DELAY_SECONDS)  # deliberate throttle before any UniFi write
            try:
                group = unifi.update_group_members(group, banned)
            except requests.RequestException:
                METRIC_UNIFI_WRITE_TOTAL.labels(result="failure").inc()
                raise
            METRIC_UNIFI_WRITE_TOTAL.labels(result="success").inc()
            METRIC_LAST_WRITE_TIMESTAMP.set(time.time())
            log.info("Synced firewall group %r -> %d members (%s)", UNIFI_GROUP_NAME, len(banned), label.lower())
    else:
        # No PUT needed since the group's already correct -- but that's still a real,
        # just-confirmed data point on "is the UniFi group in the right state," which is
        # what this metric is actually for. Without this, a cycle where nothing needed
        # to change left the gauge at its Prometheus-default 0 until the next real
        # write, making "time since last write" read as ~56 years (time() - 0) --
        # confirmed live 2026-08-13, not a hypothetical.
        METRIC_LAST_WRITE_TIMESTAMP.set(time.time())

    log.info("%s reconciliation: %d addresses should be blocked (%d already were, %d stale removed)",
              label, len(banned), len(already_banned), len(stale))
    return group, banned


def main():
    start_http_server(METRICS_PORT)
    METRIC_DRY_RUN.set(1 if DRY_RUN else 0)

    cs_key = read_secret(CROWDSEC_BOUNCER_API_KEY_FILE)
    unifi_key = read_secret(UNIFI_API_KEY_FILE)

    cs = CrowdSecClient(CROWDSEC_LAPI_URL, cs_key)
    unifi = UniFiClient(UNIFI_HOST, unifi_key, UNIFI_SITE, UNIFI_VERIFY_TLS)
    cf_allow = CloudflareAllowlist()
    if cf_allow.refresh(force=True):
        sync_cloudflare_group(unifi, cf_allow)

    log.info("Starting crowdsec-unifi-bouncer (dry_run=%s, poll_interval=%ss, reconcile_interval=%ss, group=%r, cloudflare_group=%r, metrics_port=%d)",
              DRY_RUN, POLL_INTERVAL_SECONDS, RECONCILE_INTERVAL_SECONDS, UNIFI_GROUP_NAME,
              UNIFI_CLOUDFLARE_GROUP_NAME or "(disabled)", METRICS_PORT)

    group = unifi.find_group(UNIFI_GROUP_NAME)
    if group is None:
        if DRY_RUN:
            log.info("[dry-run] Would create firewall group %r (no write performed)", UNIFI_GROUP_NAME)
            group = {"_id": "dry-run-placeholder", "name": UNIFI_GROUP_NAME, "group_members": []}
        else:
            group = unifi.create_group(UNIFI_GROUP_NAME)
            log.info("Created firewall group %r (id=%s)", UNIFI_GROUP_NAME, group.get("_id") or group.get("id"))
    else:
        log.info("Found existing firewall group %r (id=%s, %d current members)",
                  UNIFI_GROUP_NAME, group.get("_id") or group.get("id"), len(group.get("group_members", [])))

    update_policy_hits_metric(unifi)

    group, banned = reconcile(cs, unifi, cf_allow, group, label="Startup")
    last_reconcile = time.time()

    while True:
        try:
            if time.time() - last_reconcile >= RECONCILE_INTERVAL_SECONDS:
                # Periodic full reconciliation -- self-healing regardless of whether
                # the incremental `deleted` deltas below reliably capture every
                # removal (e.g. natural TTL expiry, not just explicit `cscli`
                # deletions -- never actually verified). Supersedes this cycle's
                # incremental poll entirely rather than doing both.
                group, banned = reconcile(cs, unifi, cf_allow, group, label="Periodic")
                last_reconcile = time.time()
                if cf_allow.refresh():
                    sync_cloudflare_group(unifi, cf_allow)
                update_policy_hits_metric(unifi)
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            update = cs.decisions_stream(startup=False)
            METRIC_LAST_SYNC_TIMESTAMP.set(time.time())
            new = update.get("new") or []
            deleted = update.get("deleted") or []
            # Refactored 2026-08-13 to share reconcile() with the periodic path above --
            # this used to be seeded once before the loop by the old inline startup
            # block, which no longer exists in this scope. Must default False each
            # cycle, or a cycle with zero new/deleted decisions hits `if pending_write`
            # below with the name never assigned.
            pending_write = False

            for d in new:
                if d.get("origin") not in CROWDSEC_ORIGINS:
                    continue
                ip = d["value"]
                if not is_ipv4(ip):
                    METRIC_DECISIONS_SKIPPED_TOTAL.labels(reason="ipv6").inc()
                    log.warning("Skipping %s -- IPv6 not yet supported (needs a separate UniFi group), see README", ip)
                    continue
                if cf_allow.contains(ip):
                    METRIC_DECISIONS_SKIPPED_TOTAL.labels(reason="cloudflare").inc()
                    log.warning("Skipping %s -- within Cloudflare's own IP ranges, refusing to block", ip)
                    continue
                member = normalize_member(ip)
                if member not in banned:
                    banned.add(member)
                    pending_write = True
                    METRIC_DECISIONS_TOTAL.labels(result="added").inc()
                    log.info("New decision: %s (%s, duration %s)", ip, d.get("scenario"), d.get("duration"))
            for d in deleted:
                ip = d["value"]
                member = normalize_member(ip)
                if member in banned:
                    banned.discard(member)
                    pending_write = True
                    METRIC_DECISIONS_TOTAL.labels(result="removed").inc()
                    log.info("Expired decision, unblocking: %s", ip)

            if pending_write:
                if DRY_RUN:
                    log.info("[dry-run] Would sync firewall group %r to %d members (no write performed)",
                              UNIFI_GROUP_NAME, len(banned))
                else:
                    time.sleep(API_WRITE_DELAY_SECONDS)  # deliberate throttle before any UniFi write
                    try:
                        group = unifi.update_group_members(group, banned)
                    except requests.RequestException:
                        METRIC_UNIFI_WRITE_TOTAL.labels(result="failure").inc()
                        raise
                    METRIC_UNIFI_WRITE_TOTAL.labels(result="success").inc()
                    METRIC_LAST_WRITE_TIMESTAMP.set(time.time())
                    log.info("Synced firewall group %r -> %d members", UNIFI_GROUP_NAME, len(banned))
                pending_write = False
                METRIC_BANNED_ADDRESSES.set(len(banned))

            if cf_allow.refresh():
                sync_cloudflare_group(unifi, cf_allow)
            update_policy_hits_metric(unifi)

        except requests.RequestException as e:
            log.error("Error during sync cycle: %s -- will retry next interval", e)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
