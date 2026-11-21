# 06 — Monitoring and Incident Response Plan

**Contents:** (1) setup and configuration of the MFA monitoring tool, (2) detection catalogue, (3) MFA usage reporting, (4) incident response plan and playbooks, (5) the simulated incident response drill and its results.

---

## 1. Monitoring tool setup and configuration

### 1.1 Components

| Component | Version | Purpose | Files |
|---|---|---|---|
| Wazuh manager | 4.9.2 (manager-only, no indexer/dashboard: lightweight) | Log collection, decoding, correlation, alerting | service `wazuh-manager` in `lab/docker-compose.yml` |
| Custom decoders | — | Parse Keycloak and mfa-otp-bridge events | `siem/keycloak_decoders.xml` |
| Custom rules | IDs 100500–100549 | Usage tracking and detection | `siem/keycloak_rules.xml` |
| Usage report | Python | Periodic MFA usage statistics | `scripts/mfa_usage_report.py` |
| Replay sample | — | Rule regression test | `siem/sample_events.log` |

### 1.2 Event sources

| Source | Configuration | File (shared Docker volume) | Example events |
|---|---|---|---|
| Keycloak user events | Realm *Events* enabled, listener `jboss-logging`; success level INFO, error level WARN (`--spi-events-listener-jboss-logging-*`) | `/var/log/keycloak/keycloak.log` (`kc-logs`) | `LOGIN`, `LOGIN_ERROR`, `UPDATE_CREDENTIAL`, `UPDATE_TOTP`, `REMOVE_CREDENTIAL` |
| Keycloak admin events | Realm *Admin events* enabled with representation | same file | `operationType="ACTION"` (sessions revoked), `UPDATE` (user disabled), `DELETE` credential |
| MFA details | Custom SPI adds `mfa_method` to LOGIN / LOGIN_ERROR events | same file | `mfa_method="sms-otp"`, `error="invalid_otp"` |
| mfa-otp-bridge | Writes Keycloak-compatible `key="value"` lines tagged `[mfa-otp-bridge]` | `/var/log/mfa/bridge-events.log` (`bridge-logs`) | `SEND_OTP` (+`error="rate_limited"`), `OTP_VERIFY_ERROR`, `RADIUS_AUTH(_ERROR)`, `OTP_CHANNEL_LOCKED` |

OTP values, backup codes and secrets are never written to any log; phone numbers and emails are masked.

### 1.3 Setup steps

1. **Mount the content** (already in the compose file):
   ```yaml
   volumes:
     - ../siem/keycloak_decoders.xml:/var/ossec/etc/decoders/keycloak_decoders.xml:ro
     - ../siem/keycloak_rules.xml:/var/ossec/etc/rules/keycloak_rules.xml:ro
     - kc-logs:/var/log/keycloak:ro
     - bridge-logs:/var/log/mfa:ro
   ```
2. **Enable log collection** — `scripts/wazuh_enable_ingestion.sh` (run by `setup_lab.sh`) appends `lab/wazuh/ossec-localfiles.xml` to `/var/ossec/etc/ossec.conf`:
   ```xml
   <localfile><log_format>syslog</log_format><location>/var/log/keycloak/keycloak.log</location></localfile>
   <localfile><log_format>syslog</log_format><location>/var/log/mfa/bridge-events.log</location></localfile>
   ```
   then validates the configuration with `wazuh-analysisd -t` and restarts the manager.
3. **Validate decoding and rules:**
   ```bash
   cd lab
   docker compose exec -T wazuh-manager /var/ossec/bin/wazuh-logtest < ../siem/sample_events.log
   ```
   Expected rule IDs: 100501, 100503, 100507, 100508, 100509, 100522, 100523, 100524, 100526, 100532 (verify check 16).
4. **Watch alerts:**
   ```bash
   docker compose exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.log
   docker compose exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json
   ```

### 1.4 Decoder design

One parent decoder (`keycloak-events`) matches either tag `[org.keycloak.events]` or `[mfa-otp-bridge]`. Twelve **sibling** child decoders (same name) each extract one field, because Keycloak does not guarantee field order. Extracted fields: `keycloak.type`, `keycloak.operation`, `keycloak.realm`, `keycloak.client_id`, `keycloak.user_id`, `srcip`, `keycloak.error`, `keycloak.username` (+ `dstuser`), `keycloak.mfa_method`, `keycloak.channel`, `keycloak.resource_path`. Word-boundary anchors stop `type=` matching inside `auth_type=`.

## 2. Detection catalogue

### 2.1 MFA usage tracking (informational)

| Rule | Level | Tracks |
|---|---|---|
| 100501 | 3 | Successful sign-in (with MFA method) |
| 100502 | 5 | Failed sign-in (reason) |
| 100503 | 6 | Failed second factor (`invalid_otp`, `expired_code`, `too_many_attempts`, WebAuthn errors) |
| 100520 | 3 | OTP code sent |
| 100525 | 3 | OTP verified / OTP verification failed at the bridge |
| 100526 | 4 | **Fallback MFA used** (SMS, Email, backup code) |
| 100531 | 3 | VPN sign-in with password + TOTP |

### 2.2 Suspicious-activity detections

| Rule | Level | Logic | Threshold | Response playbook |
|---|---|---|---|---|
| 100504 | 9 | Sign-in on a locked/disabled account | each | §4.3 |
| 100505 | 8 | User changed/removed an MFA credential | each | Verify with user; §4.5 |
| 100506 | 9 | Admin deleted a user's credential | each | Verify change ticket; §4.5 |
| 100510 | 10 | Brute force: failures for one user from one IP | ≥ 6 in 120 s | §4.3 |
| 100511 | 13 | Sign-in right after a brute-force burst | 300 s | §4.3 (treat as compromise) |
| 100512 | 10 | Password spraying: failures for many users from one IP | ≥ 8 in 180 s | §4.3 |
| 100521 | 7 | OTP send refused (rate limit, locked, delivery failure) | each | §4.2 |
| **100522** | **11** | **OTP bombing / MFA fatigue**: OTP requests for one user | ≥ 5 in 180 s | **§4.2** |
| **100523** | **11** | **Repeated MFA failures** for one user | ≥ 5 in 180 s | **§4.2** |
| **100524** | **14** | **Sign-in after OTP bombing / MFA failures** | 600 s | **§4.2 — compromise** |
| 100532 | 5 | VPN authentication failure | each | — |
| 100533 | 10 | VPN brute force for one user | ≥ 6 in 120 s | §4.3 |
| 100540 | 10 | Same user signed in from 2+ IPs | 15 min | §4.6 |

Containment audit trail: 100507 sessions revoked, 100508 account modified by admin, 100509 OTP channel locked/unlocked.

### 2.3 Alert handling SLAs

| Alert level | Severity | Triage SLA | Notification |
|---|---|---|---|
| 12–15 | Critical | 15 min, 24×7 | SOC on-call phone + IR lead |
| 10–11 | High | 30 min | SOC queue + on-call |
| 7–9 | Medium | 4 business hours | SOC queue |
| 3–6 | Low / informational | Weekly review / usage report | — |

## 3. MFA usage reporting

```bash
python3 scripts/mfa_usage_report.py --hours 24     # Markdown on screen + docs/evidence/mfa_usage_<UTC>.md
```

The report shows successful sign-ins by MFA method, fallback share, failed sign-ins and failed second-factor attempts by reason, OTP sends and rate-limit refusals, VPN successes/failures, the users with most failures and alert counts by rule. It is reviewed monthly by the IAM team (policy A.3.10; HIPAA §164.308(a)(1)(ii)(D)) and after every drill.

## 4. Incident Response Plan for MFA-related incidents

### 4.1 Organisation, severity and phases

| Role | Who | Duties |
|---|---|---|
| Incident commander | SOC lead | Owns the incident, decisions, timeline |
| SOC analyst | On-call analyst | Triage, investigation, containment via Admin APIs |
| IAM engineer | IAM team | Credential resets, flow changes, directory actions |
| Service desk | Service desk lead | User contact, identity verification |
| DPO / Legal | DPO | Regulatory notification decisions (GDPR, HIPAA) |
| Communications | HR / Comms | Staff and customer messaging |

| Severity | Definition | Examples |
|---|---|---|
| SEV-1 | Confirmed account compromise or privileged/MFA infrastructure compromise | Rule 100511 or 100524; admin MFA removed without ticket |
| SEV-2 | Active attack, no confirmed compromise | Rules 100510, 100512, 100522, 100523, 100533 |
| SEV-3 | Suspicious but isolated | Single 100504, 100540 with plausible explanation |

**Phases (all playbooks):** Preparation → Detection & analysis → Containment → Eradication → Recovery → Post-incident review.

**Preparation (standing):** this plan; Admin API access for the SOC (Keycloak service account with `manage-users`); bridge admin key; runbooks scripted in `scripts/simulate_ir_drill.py`; quarterly drill; contact list; evidence folder conventions.

**Common containment commands**

```bash
TOKEN=$(curl -s -d grant_type=password -d client_id=admin-cli -d username=kcadmin -d "password=$KC_ADMIN_PASSWORD" \
  http://localhost:8080/realms/master/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
API=http://localhost:8080/admin/realms/enterprise-realm
UID=$(curl -s -H "Authorization: Bearer $TOKEN" "$API/users?username=j.doe&exact=true" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
curl -s -X POST -H "Authorization: Bearer $TOKEN" "$API/users/$UID/logout"                         # revoke all sessions
curl -s -H "Authorization: Bearer $TOKEN" "$API/users/$UID/sessions"                               # confirm: []
curl -s -X POST -H "X-Bridge-Key: $BRIDGE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"username":"j.doe","operator":"soc","reason":"incident"}' http://localhost:8000/admin/lock   # stop OTP issuance
# disable account: GET the user representation, set "enabled": false, PUT it back (see simulate_ir_drill.py)
curl -s -H "Authorization: Bearer $TOKEN" "$API/attack-detection/brute-force/users/$UID"            # lockout state
```

### 4.2 Playbook — OTP bombing / MFA fatigue / repeated MFA failures (rules 100522, 100523, 100524)

| Phase | Actions |
|---|---|
| Detection & analysis | Confirm the alert in `alerts.json`; pull the user's events (`grep 'username="<user>"'` in both logs) for the last hour; establish whether the password stage succeeded (it did if OTP requests were made); identify source IPs; check for 100524 (success after the burst) → SEV-1. Contact the user by a known channel: did they request the codes? |
| Containment | Revoke all sessions; disable the account; lock the OTP channel at the bridge; if the source IP is external and malicious, block it at the perimeter. |
| Eradication | Force a directory password reset (the attacker has the password); remove any authenticator registered since the attack began; review mailbox forwarding rules if Email OTP was used. |
| Recovery | Identity-verified reset via the service desk (SOP B.2); re-enable account; unlock OTP channel; user re-enrols; move the user from the SMS/Email tier to an authenticator app or hardware key where possible; monitor the account for 14 days. |
| Post-incident | Where the password came from (reuse, phishing, breach); was the rate limit sufficient; update awareness campaign. |

### 4.3 Playbook — Brute force / password spraying / VPN brute force (100510, 100511, 100512, 100533, 100504)

Analyse source IPs and targeted accounts; if 100511 fired, treat as SEV-1 and follow §4.2 containment for that user. Block abusive IPs; confirm Keycloak's temporary lockout engaged (`attack-detection` API); notify targeted users to change reused passwords; for spraying, force password resets for accounts sharing common passwords; after the attack, clear lockouts (`DELETE /attack-detection/brute-force/users/{id}`).

### 4.4 Playbook — Lost or stolen authenticator / suspected token compromise

Follow SOP B.3 (policy document 05): verify identity, delete the authenticator, revoke sessions within 1 h (15 min privileged), disable and reset if theft is suspected, review events since the time of loss, re-enrol with backup codes or a second key.

### 4.5 Playbook — Compromised SMS or Email OTP channel (SIM swap, mailbox takeover) and MFA tampering (100505, 100506)

Indicators: the user reports no mobile signal / unexpected carrier messages; OTP sign-ins from new IPs; unexpected `UPDATE_CREDENTIAL`/`REMOVE_CREDENTIAL` or admin credential deletion. Contain: revoke sessions, lock the OTP channel, disable the account; contact the carrier (SIM swap) or mail team (mailbox: remove forwarding rules, reset password). Eradicate: remove attacker-registered authenticators; for admin tampering, verify the change ticket and review all admin events by that administrator. Recover: move the user to TOTP or WebAuthn; re-enable.

### 4.6 Playbook — Anomalous sessions (100540)

Compare IPs with the user's known locations/VPN egress; if unexplained, contact the user; if not recognised, follow §4.2 containment.

### 4.7 Communication and regulatory notification

| Trigger | Action | Deadline |
|---|---|---|
| Any SEV-1 | IR commander informs CISO and DPO | Immediately |
| Personal data breach likely (GDPR) | DPO assesses risk; notify the supervisory authority (Art. 33) | Within **72 hours** of awareness |
| High risk to individuals (GDPR) | Inform affected individuals (Art. 34) | Without undue delay |
| Breach of unsecured PHI (HIPAA) | Notify affected individuals (§164.404); HHS (§164.408); media if > 500 residents of a state (§164.406) | Without unreasonable delay, **≤ 60 days** of discovery |
| All incidents | Record in incident register with timeline and evidence | Close of incident |

### 4.8 Evidence handling

Store logs, alerts and timelines under `docs/evidence/<incident-id>/`; record UTC timestamps and who collected each item; do not edit originals (write analysis to separate files); retain per policy A.3.10.

## 5. Simulated incident response drill

### 5.1 Drill design

| Item | Detail |
|---|---|
| Script | `scripts/simulate_ir_drill.py` (standard library only; `--no-recover` leaves the account locked) |
| Scenario | Credential stuffing → OTP bombing → OTP guessing against `j.doe` (SMS/Email fallback tier) |
| Phases | 0 baseline legitimate sign-in (creates a real SSO session) · 1 four leaked passwords then the correct one · 2 six SMS OTP requests · 3 six OTP guesses · 4 wait for Wazuh alerts 100522/100523 · 5 containment: revoke sessions, disable account (directory password scramble if the read-only federation refuses), lock OTP channel; then prove containment · 6 evidence collection + offline `wazuh-logtest` replay · 7 recovery |
| Pass criteria | Detection alert raised; all sessions revoked; victim's SSO cookie no longer valid; stolen password refused; OTP channel locked; attacker never obtains a session |
| Evidence | `docs/evidence/ir_drill_<UTC>/`: `drill_console.log`, `timeline.json`, `keycloak_events.log`, `bridge_events.log`, `wazuh_alerts.json`, `wazuh_logtest_replay.txt`, `after_action_report.md` |
| Run | `python3 scripts/simulate_ir_drill.py` (or `./scripts/run_all.sh`) |

### 5.2 Drill results and logs

The section between the markers below is written by `simulate_ir_drill.py` from what the run actually observed (timeline, alerts, metrics, outcome checks). It is replaced on every run; the full logs remain in the evidence folder.

<!-- DRILL-RESULTS:BEGIN -->
*Drill not yet executed in this copy of the repository. Run `python3 scripts/simulate_ir_drill.py` against the running lab; this block is then replaced with the after-action report and the evidence folder path.*
<!-- DRILL-RESULTS:END -->
