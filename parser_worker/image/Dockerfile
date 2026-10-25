# Static review image only; execution approval is separate. Root context uses
# the Dockerfile-specific whitelist, including eight hash-verified offline wheels.
# Reuses reviewed immutable source pin, not the smoke image identity/approval.
FROM --platform=linux/amd64 docker.io/library/python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS parser_build
COPY parser_worker/image/requirements.lock /build/requirements.lock
COPY parser_worker/image/stage_runtime.py /build/stage_runtime.py
COPY var/parser-wheelhouse/linux-amd64-cp312/annotated_types-0.8.0-py3-none-any.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/defusedxml-0.7.1-py2.py3-none-any.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/et_xmlfile-2.0.0-py3-none-any.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/openpyxl-3.1.5-py2.py3-none-any.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/pydantic-2.14.1-py3-none-any.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/typing_extensions-4.16.0-py3-none-any.whl /build/wheels/
COPY var/parser-wheelhouse/linux-amd64-cp312/typing_inspection-0.4.4-py3-none-any.whl /build/wheels/
RUN ["/usr/local/bin/python", "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-cache-dir", "--no-index", "--find-links=/build/wheels", "--only-binary=:all:", "--require-hashes", "--no-deps", "--no-compile", "--target=/opt/parser-vendor", "-r", "/build/requirements.lock"]
RUN ["/usr/local/bin/python", "-I", "-B", "/build/stage_runtime.py"]

FROM scratch
COPY --from=parser_build /opt/parser-runtime/ /
COPY --from=parser_build /opt/parser-vendor/ /opt/sheetsafe/vendor/
LABEL org.opencontainers.image.title="SheetSafe dedicated parser foundation" \
      io.sheetsafe.policy="sheetsafe-parser-policy-v1" \
      io.sheetsafe.execution="disabled"
ENV LANG=C.UTF-8 \
    HOME=/nonexistent \
    PATH=/usr/local/bin
COPY --chown=0:0 --chmod=0444 ingestion/__init__.py ingestion/contracts.py ingestion/parser_jobs.py /opt/sheetsafe/app/ingestion/
COPY --chown=0:0 --chmod=0444 parser_worker/__init__.py parser_worker/common.py parser_worker/csv_parser.py parser_worker/xlsx_archive.py parser_worker/xlsx_parser.py parser_worker/entrypoint.py /opt/sheetsafe/app/parser_worker/
COPY --chown=0:0 --chmod=0444 parser_worker/image/bootstrap.py /opt/sheetsafe/bootstrap.py
USER 10001:10001
WORKDIR /work
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/python3.12", "-I", "-S", "-B", "-u", "/opt/sheetsafe/bootstrap.py"]
CMD []
