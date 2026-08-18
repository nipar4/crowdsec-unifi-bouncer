# Multi-stage build — final image is Google's actual distroless Python (no shell, no
# package manager, nonroot by default). Switched from a plain python:slim single-stage
# build 2026-08-13, at the user's request, after confirming 11notes/distroless has no
# Python support at all (static-binaries-only base, would need a full static CPython
# compile or a language rewrite — impractical for this small a script). This achieves
# the same real security property (minimal shipped attack surface) without a rewrite.
#
# Builder base is deliberately python:3.14-slim-bookworm, not just "-slim" — Debian
# version must match the distroless target (python3-debian12) for glibc/library
# compatibility, per Google's own distroless build guidance.
FROM python:3.14-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
WORKDIR /app
COPY --from=builder /app/deps /app/deps
COPY crowdsec_unifi_bouncer.py .
ENV PYTHONPATH=/app/deps
# org.opencontainers.image.version, added 2026-08-18 for the new Docker Hub
# publish pipeline (crowdsec-unifi-bouncer-build.yml) -- lets this repo's
# existing check_version_comments.py CI job validate the pinned digest's
# trailing "# vX.Y.Z" comment automatically, same mechanism already used
# for every other tracked image (see that script's own docstring). Bump
# this by hand alongside any real change, matching how a human would tag
# a release -- no git-tag-driven automation for a service this size.
LABEL org.opencontainers.image.version="1.0.0"
ENTRYPOINT ["python3", "-u", "crowdsec_unifi_bouncer.py"]
