# Security Policy

## Reporting a Vulnerability

Please do **not** open public GitHub issues for suspected security vulnerabilities. Instead, use GitHub's private **Report a vulnerability** advisory workflow on this repository so a fix can be coordinated before public disclosure.

## Operational Hardening Notes

1. **Debug & Ingestion Routes (`/api/v1/ops/*`)**: Designed for local debugging and internal ingestion pipelines. In shared or production deployments, bind the service behind an authenticated gateway and set `PROVLOOM_INGEST_ROOT` to a dedicated read-only staging directory.
2. **Tenant & Source Scope Headers (`X-Tenant-Id`, `X-Allowed-Sources`)**: Enforce and inject these headers at your upstream reverse proxy / API gateway rather than trusting unauthenticated client headers.
3. **Database Credentials**: Override default development credentials in `.env` / `docker-compose.yml` before non-local deployment.
