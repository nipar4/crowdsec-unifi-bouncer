## crowdsec-unifi-bouncer

A small, self-authored [CrowdSec](https://www.crowdsec.net/) bouncer that syncs
CrowdSec's local decisions to a UniFi (UDM Pro) firewall address group.

**Full installation instructions are on GitHub, not here — read them before deploying:**

**https://github.com/nipar4/crowdsec-unifi-bouncer#readme**

Group-membership syncing alone does not block any traffic. A required one-time manual
UniFi firewall policy setup step is covered in full in the GitHub README — deploying
without it means this container will run and log success while doing nothing to real
traffic.
