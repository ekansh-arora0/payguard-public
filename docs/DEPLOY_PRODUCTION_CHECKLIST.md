# PayGuard Production Launch Checklist

This checklist is for **pre-internet exposure** hardening and launch readiness.

## 1) Secrets

- [ ] Generate and set a strong backend admin token:
  - `python -c "import secrets; print(secrets.token_urlsafe(48))"`
  - Set `PAYGUARD_API_ADMIN_TOKEN=<value>` in `.env`
- [ ] Ensure demo key is disabled in production:
  - `PAYGUARD_ALLOW_DEMO_KEY=false`
- [ ] Rotate database and cache credentials before launch:
  - `MONGO_ROOT_PASSWORD`
  - `REDIS_PASSWORD`
  - `ENTERPRISE_API_TOKEN`
- [ ] Confirm `.env` is never committed (already gitignored).

## 2) Network Exposure

- [ ] Expose only `80/443` publicly (reverse proxy).
- [ ] Keep MongoDB and Redis internal-only (no public port mapping).
- [ ] Verify host firewall/security group allows only:
  - inbound: `80`, `443`
  - SSH restricted by source IP (admin-only)

## 3) Authentication / Authorization

- [x] API key issuance endpoint is admin-protected:
  - `POST /api/v1/api-key/generate` requires `X-Admin-Token`
- [ ] Enterprise dashboard hardening:
  - Current: static bearer token
  - Next: JWT/OIDC (Okta/Auth0/Google Workspace) + role-based access

## 4) Abuse Protection

- [x] Per-key quotas are enforced in `backend/auth.py`.
- [x] Per-IP limits are enforced via `slowapi` on hot endpoints.
- [x] Security telemetry added (`payguard_security_events_total`).
- [x] Prometheus alerts added for auth-failure and rate-limit spikes.

## 5) Reliability / Operations

- [x] Health checks and auto-restart configured in compose.
- [x] Backup job configured (Mongo backup container).
- [ ] Backup restore drill (must be executed before launch):
  1. Create disposable DB/container
  2. Restore latest backup
  3. Verify collections + sample records + startup passes

Suggested restore command pattern (adjust paths):

```bash
mongorestore \
  --host localhost \
  --port 27017 \
  --username "$MONGO_ROOT_USER" \
  --password "$MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  --gzip \
  --archive=backups/<latest>.archive.gz
```

## 6) Legal / Commercial

Before charging customers, publish and link these docs on your website:

- [ ] Terms of Service
- [ ] Privacy Policy (existing draft in `docs/PRIVACY_POLICY.md`)
- [ ] Data Processing Agreement (DPA)
- [ ] Service Level Agreement (SLA)
- [ ] Incident Response Policy (IRP)

Minimum commercial controls:

- [ ] Support email and security contact
- [ ] Vulnerability disclosure policy
- [ ] Data retention and deletion policy

## 7) Go-Live Command Sequence

```bash
# 1) Validate compose config with env
docker compose -f docker-compose.prod.yml config

# 2) Launch
docker compose -f docker-compose.prod.yml up -d --build

# 3) Verify health
curl -f https://<your-domain>/api/v1/health

# 4) Verify metrics endpoint internally
curl -f http://localhost:8002/api/v1/metrics
```

## 8) Post-Launch 24h Monitoring

- [ ] Watch error rate and latency dashboards
- [ ] Watch auth-failure/rate-limit alerts
- [ ] Check backup logs
- [ ] Review threat detection and false-positive reports
