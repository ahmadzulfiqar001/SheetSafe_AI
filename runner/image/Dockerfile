# Image definition only: effective runtime isolation remains UNVERIFIED.
# Official Python index digest verified via registry metadata on 2026-10-22.
FROM docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS python_source

# Copy runtime files from the reviewed source, without inheriting its image ENV.
# Preserve the runtime/library closure until isolated compatibility tests exist.
# Shells, pip and headers remain; selective filesystem minimization is pending.
FROM scratch
COPY --from=python_source / /

LABEL org.opencontainers.image.title="SheetSafe fixed smoke fixture" \
      org.opencontainers.image.version="smoke-v1" \
      io.sheetsafe.policy="sheetsafe-smoke-policy-v1"

ENV LANG=C.UTF-8 \
    HOME=/nonexistent \
    PATH=/usr/local/bin:/usr/bin:/bin

COPY --chown=0:0 --chmod=0444 bootstrap.py /opt/sheetsafe/bootstrap.py

USER 10001:10001
WORKDIR /work
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/python", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"]
CMD ["smoke-v1"]
