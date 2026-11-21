# 04 — MFA Configuration Guides

Step-by-step setup and testing for each MFA method (SMS OTP, Email OTP, app-based OTP, biometrics, hardware tokens) and integration guides for SSO and VPN / remote access. Every setting below is already applied by the lab files referenced; the console paths let you inspect or reproduce them by hand.

**Conventions**

- Keycloak admin console: `http://localhost:8080/admin` → realm **enterprise-realm** (sign in as `kcadmin`, password `KC_ADMIN_PASSWORD` in `lab/.env`).
- Account console (end users): `http://localhost:8080/realms/enterprise-realm/account`.
- Directory test users: password `Corp!Lab2026` (lab only).
- "Check N" refers to the numbered checks of `scripts/verify_mfa.py`.

---

## 1. Lab deployment

**Prerequisites:** Docker Desktop (Windows: WSL 2 backend; run the scripts from a WSL Ubuntu shell) or Docker Engine with Compose v2; 8 GB RAM for Docker; Python 3.9+; free local ports 389, 1194/udp, 1812/udp, 5000, 5001, 8000, 8025, 8080.

```bash
cd enterprise-mfa-bia
./scripts/setup_lab.sh            # secrets -> build -> start -> health checks -> kcadm config -> LDAP sync -> Wazuh -> verify
./scripts/run_all.sh              # setup + baseline assessment + verification + IR drill + usage report
./scripts/teardown_lab.sh --purge # remove everything (keeps lab/.env)
```

**Without local Docker:** push the repository to GitHub and run the workflow `.github/workflows/mfa-lab-ci.yml`; it executes `run_all.sh` on a GitHub-hosted runner and publishes the evidence as a downloadable artifact (see README).

`setup_lab.sh` creates `lab/.env` with random values for every secret (client secrets, RADIUS secret, OTP HMAC key, bridge API key, admin passwords) and `chmod 600`.

## 2. Directory integration (Active Directory role)

**Files:** `lab/openldap/ldif/50-enterprise-directory.ldif`, realm component `corp-ldap` in `lab/keycloak/realm/enterprise-realm.json`.

1. Admin console → **User federation** → **corp-ldap**.
   - Vendor *Other*; Connection URL `ldap://openldap:389`; Bind DN `cn=readonly,dc=corp,dc=enterprise,dc=local`.
   - Users DN `dc=corp,dc=enterprise,dc=local`, search scope *Subtree*, filter `(objectClass=inetOrgPerson)`.
   - Edit mode **READ_ONLY**, Import users *On*, periodic changed-user sync 300 s, full sync 3600 s.
2. **Mappers** tab: `username`(uid), `email`(mail), `first name`/`last name`, `mobile`, `department`(departmentNumber), `job title`, and `ldap-groups-to-realm-roles` (role-ldap-mapper, `ou=Groups`, `groupOfNames`, `member`, realm roles).
3. Sync: *Action → Sync all users*, or `kcadm.sh create user-storage/corp-ldap/sync?action=triggerFullSync -r enterprise-realm` (done by `setup_lab.sh`).
4. Assign a user to an MFA tier by adding them to `cn=mfa-tier-webauthn|mfa-tier-totp|mfa-tier-otp-fallback,ou=Groups` in the directory.

**Test:** *Users* lists 10 directory users + `svc.mfa-probe`; open `j.doe` → *Role mapping* shows `mfa-tier-otp-fallback`. Check 2 verifies the directory bind.

**Production (Active Directory):** vendor *Active Directory*, `ldaps://dc01.corp.example:636`, username attribute `sAMAccountName`, UUID `objectGUID`, user object classes `person, organizationalPerson, user`; tier groups are AD security groups.

## 3. Authentication flow (shared by all methods)

**File:** `authenticationFlows` in the realm JSON. Admin console → **Authentication** → flow **enterprise-browser** (bound as *Browser flow*).

| Execution / sub-flow | Requirement | Config |
|---|---|---|
| Cookie | Alternative | — |
| enterprise-browser-forms → Username Password Form | Required | — |
| → initial-enrolment-otp | Conditional | `Condition - no MFA enrolled yet` + `Condition - user role` (NOT fallback) → `SMS / Email OTP (mfa-otp-bridge)` purpose *enrolment* |
| → tier-aal3-phishing-resistant | Conditional | role `mfa-tier-webauthn` → aal3-factor: [WebAuthn + assurance note AAL3] **or** [backup code + note AAL2] |
| → tier-aal2-totp | Conditional | role `mfa-tier-totp` → aal2-factor: [OTP Form + note AAL2] **or** [backup code + note AAL2] |
| → tier-fallback-sms-email-otp | Conditional | role `mfa-tier-otp-fallback` → `SMS / Email OTP (mfa-otp-bridge)` purpose *signin* |
| → tier-none-deny | Conditional | NOT webauthn AND NOT totp AND NOT fallback → *Deny access* |

The custom executions come from the SPI in `lab/keycloak/providers/mfa-bridge-authenticator/` (built into the Keycloak image by `lab/keycloak/Dockerfile`).

---

## 4. SMS-based OTP (initial and fallback authentication)

**Components:** Keycloak SPI `bridge-otp-authenticator` → `mfa-otp-bridge` `/otp/send`, `/otp/verify` → mock SMS gateway (`http://localhost:8000/sms/inbox`).

### Configuration

1. **Bridge** (`lab/docker-compose.yml`, service `mfa-otp-bridge`): `OTP_TTL_SECONDS=300`, `OTP_MAX_ATTEMPTS=5`, `OTP_SEND_LIMIT_PER_MINUTE=3`, `OTP_SEND_LIMIT_PER_HOUR=10`, `OTP_HMAC_KEY` and `BRIDGE_API_KEY` from `.env`.
2. **Keycloak** environment: `MFA_BRIDGE_URL=http://mfa-otp-bridge:8000`, `MFA_BRIDGE_API_KEY` (sent as header `X-Bridge-Key`).
3. **Destination:** the user's `mobile` attribute, mapped from LDAP `mobile`.
4. **Flow:** executions configured with alias `bridge-otp` (purpose *signin*, fallback tier) and `bridge-otp-enrolment` (purpose *enrolment*, initial authentication).
5. **Production:** replace `deliver_sms()` in `lab/mfa-otp-bridge/app/main.py` with the SMS provider's API call; set `SMS_OUTBOX_ENABLED=false`.

### User steps (j.doe)

1. `http://localhost:5000` → *Sign in* → `j.doe` / password.
2. Choose **Text message to \*\*\*\*\*\*\*007**.
3. Read the code on the mock handset `http://localhost:8000/sms/inbox`, enter it, select **Verify**.

### Test

| Test | Expected | Automated |
|---|---|---|
| Correct code | Portal shows `AAL2` / `sms-otp` | Check 7 |
| Wrong code | "The code is not correct…", Keycloak `LOGIN_ERROR error="invalid_otp"` | Check 5 (bridge), drill |
| Same code twice | Second use rejected | Check 5 |
| 4th code request within a minute | "Too many codes were requested…", bridge `SEND_OTP error="rate_limited"` | Drill |
| Initial authentication | First sign-in of a new TOTP/WebAuthn user requires SMS/Email OTP before enrolment | Check 9 |

**Troubleshooting:** "verification service is unavailable" → `docker compose logs mfa-otp-bridge`; code never arrives → check the user's `mobile` attribute in *Users → Attributes*.

## 5. Email-based OTP (initial and fallback authentication)

**Components:** same SPI and bridge; delivery by SMTP to Mailpit (`mailpit:1025`, inbox `http://localhost:8025`). Keycloak's own SMTP settings (*Realm settings → Email*: host `mailpit`, port 1025, from `iam-noreply@corp.enterprise.local`) are also set for system emails.

### User steps (l.fernandes)

1. Sign in as `l.fernandes`, choose **Email to l\*\*\*@corp.enterprise.local**.
2. Open Mailpit, read "Your Enterprise Corp sign-in code", enter the code.

### Test

| Test | Expected | Automated |
|---|---|---|
| Correct code | Portal `AAL1` / `email-otp` | Check 8 |
| Email-OTP session opens `/finance` | Denied: "Higher assurance required" (AAL2 needed) | Check 8 |
| Wrong, replayed, expired codes | Rejected | Check 4 |
| Screen reader | Code field announced as "Verification code", errors read automatically, no time pressure under 5 min | Manual |

**Production:** point `SMTP_HOST`/`SMTP_PORT` at the corporate relay with TLS and authentication; publish SPF/DKIM so codes are not filtered as spam.

## 6. App-based OTP (Google Authenticator / Microsoft Authenticator)

### Configuration

1. *Authentication → Policies → OTP policy*: type **Time based**, algorithm **SHA1**, digits **6**, period **30**, look-ahead **1**, *Reusable token* **Off**. (SHA-1 is used because both apps ignore SHA-256 parameters.)
2. Tier flow `tier-aal2-totp` → `aal2-totp`: *OTP Form* (Required) + *MFA assurance note* (`totp`, `AAL2`, credential type `otp`).
3. *Required actions*: **Configure OTP** enabled (Keycloak adds it automatically when a TOTP-tier user has no authenticator).

### User steps (f.dsouza / m.rao)

1. First sign-in → initial SMS/Email OTP (§4/§5).
2. *Mobile Authenticator Setup* page: in Google or Microsoft Authenticator choose *Add account → Scan QR code*.
3. Enter the 6-digit code from the app and a device name (e.g. "Pixel 8") → **Submit**.
4. Later sign-ins: password → 6-digit code from the app.

### Test

| Test | Expected | Automated |
|---|---|---|
| Valid code | Portal `AAL2` / `totp`; `/finance` allowed; `/admin` denied | Check 6 |
| Same code reused within the 30-s window | Rejected (reuse forbidden) | Scripts wait for a fresh window |
| Clock skew of one step | Accepted (look-ahead 1) | Manual |

## 7. Biometrics (WebAuthn platform authenticator: fingerprint / facial recognition)

### Configuration

1. *Authentication → Policies → WebAuthn Policy*: relying party name "Enterprise Corp IAM", signature algorithms **ES256, RS256**, RP ID empty (= `localhost`), attestation *not specified*, authenticator attachment *not specified* (allows platform **and** roaming), user verification **preferred**.
2. *WebAuthn Passwordless Policy* (passkeys): resident key **Yes**, user verification **required**.
3. Tier flow `tier-aal3-phishing-resistant` → `aal3-webauthn`: *WebAuthn Authenticator* (Required) + *MFA assurance note* (`webauthn`, `AAL3`, credential type `webauthn`).
4. *Required actions*: **Webauthn Register** enabled.

### User steps (a.mehta / p.nair)

1. Use `http://localhost:8080` / `http://localhost:5000` — **not** `127.0.0.1`: WebAuthn requires a secure context and the RP ID `localhost`.
2. First sign-in → initial OTP → *Security key registration* → **Register**.
3. The browser offers *This device*: confirm with **Windows Hello** (face or fingerprint) or **Touch ID**. Name the authenticator (e.g. "Laptop Windows Hello").
4. Later sign-ins: password → "Sign in with your security key" → fingerprint/face.

### Test

| Test | Expected | Automated |
|---|---|---|
| Registration + sign-in | Portal `AAL3` / `webauthn` | Check 9 (virtual platform authenticator: transport `internal`, user verified) |
| Phishing resistance | A look-alike origin (e.g. `http://127.0.0.1:8080`) cannot use the credential | Manual: open via 127.0.0.1 → browser refuses |
| Real device | Windows Hello / Touch ID prompt appears and succeeds | Manual (record a screenshot) |

The automated check uses `VirtualAuthenticator` in `scripts/lab_common.py`, a software FIDO2 authenticator (ECDSA P-256, "none" attestation) that produces the same messages a laptop's biometric authenticator does after the fingerprint/face match. It proves the server-side configuration; the biometric match itself happens on the device and is tested manually.

## 8. Hardware tokens (FIDO2 roaming authenticator: YubiKey)

### Configuration

Same WebAuthn policy as §7 (attachment *not specified* allows roaming keys). Optional hardening for production: attestation *direct* and *Acceptable AAGUIDs* limited to the approved YubiKey models; user verification *required* (forces the key PIN).

### User steps (r.iyer / s.kumar)

1. Set a FIDO2 PIN on the key (Yubico Authenticator → FIDO2 → Set PIN).
2. First sign-in → initial OTP → **Register** → choose *Security key* / *USB or NFC* → insert → PIN → touch.
3. Register a **second key** in the account console (*Signing in → Security key → Set up*) and store it securely as backup.
4. Generate backup codes (§8.1).

### Test

| Test | Expected | Automated |
|---|---|---|
| Registration + sign-in | Portal `AAL3` / `webauthn` | Check 10 (virtual YubiKey: transport `usb`) |
| Admin area | `/admin` granted (AAL3 + `it-admins`) | Check 10 |
| Key removed | Sign-in offers backup code (AAL2, `/admin` denied) | Manual |

### 8.1 Backup codes (recovery authentication codes)

1. Feature enabled in the Keycloak image (`KC_FEATURES=recovery-codes` in `lab/keycloak/Dockerfile`); required action **Recovery Authentication Codes** enabled by `setup_lab.sh`.
2. Users: account console → *Signing in* → *Recovery authentication codes* → *Set up* → save the 12 codes → confirm.
3. Sign-in with a code: on the TOTP/WebAuthn page choose **Try another way → Recovery Authentication Code**, enter the requested code number. The session is marked `recovery-code` / `AAL2`.
4. **Test:** Check 11 (generates codes for `svc.mfa-probe`, signs in with the requested code).

---

## 9. Integration guide — Single Sign-On (corp-portal, hr-portal)

### 9.1 Register an application (Keycloak)

1. *Clients → Create client*: type **OpenID Connect**, client ID `corp-portal`.
2. *Capability config*: **Client authentication On**, *Standard flow* On, *Direct access grants* Off.
3. *Login settings*: Root URL `http://localhost:5000`, Valid redirect URIs `http://localhost:5000/callback`, Valid post-logout redirect URIs `http://localhost:5000/`, Web origins `http://localhost:5000`.
4. *Advanced → PKCE method*: **S256**.
5. *Client scopes → corp-portal-dedicated → Add mapper*:
   - *User Session Note* `mfa_method` → claim `mfa_method`; *User Session Note* `aal` → claim `aal` (ID, access, userinfo tokens).
   - *User Attribute* `department` → claim `department`.
   - *User Realm Role* → claim `realm_roles` (multivalued).
6. *Credentials*: copy the client secret to the application (`CORP_PORTAL_CLIENT_SECRET` in `.env`).
7. Repeat for `hr-portal` (port 5001) — already in the realm import.

### 9.2 Application side (`lab/corp-portal/app.py`)

- `/login`: builds the authorization request with `state`, `nonce` and PKCE `code_challenge`.
- `/callback`: exchanges the code over the back channel (`http://keycloak:8080`), verifies the ID token signature against JWKS, `iss = http://localhost:8080/realms/enterprise-realm`, `aud = client_id`, `nonce`.
- Authorisation decorator `require_assurance("AAL2")` on `/finance`, `require_assurance("AAL3", role="it-admins")` on `/admin`.
- `/logout`: RP-initiated logout with `id_token_hint`.

### 9.3 Test

| Test | Expected | Automated |
|---|---|---|
| Sign in to corp-portal | MFA once, `/me` shows identity, roles, method, AAL | Check 6 |
| Then open hr-portal | Signed in without any prompt (SSO) | Check 6b |
| Assurance enforcement | `/finance` needs AAL2, `/admin` needs AAL3 + it-admins | Checks 6, 8, 10 |
| Sign out | Keycloak session ended; next visit asks for credentials | Manual |

## 10. Integration guide — VPN and remote access (OpenVPN + RADIUS)

### 10.1 Keycloak

1. Client `vpn-radius`: confidential, **Direct access grants On**, Standard flow Off.
2. *Advanced → Authentication flow overrides → Direct grant flow*: **vpn-direct-grant** (Username validation → Password → OTP, all Required).
3. Users need role `vpn-users` (LDAP group `cn=vpn-users`) and an enrolled TOTP.

### 10.2 mfa-otp-bridge (RADIUS adapter)

`/radius/authenticate` accepts requests only from the `freeradius` container, splits `SCRV1:base64(password):base64(code)` or `password` + 6 digits, calls the Keycloak token endpoint with `grant_type=password&totp=<code>`, checks `vpn-users`, closes the Keycloak session, returns **204** (accept) or **401** (reject) and logs `RADIUS_AUTH` / `RADIUS_AUTH_ERROR`.

### 10.3 FreeRADIUS (`lab/freeradius/`)

- `raddb/clients.conf`: client `openvpn-gateway`, shared secret injected at start from `RADIUS_SHARED_SECRET`.
- `raddb/rest`: `authenticate { uri = ".../radius/authenticate", method = post, body = json, auth = basic }`.
- `raddb/mfa-site`: `authorize { Auth-Type := rest }`, `authenticate { Auth-Type rest { rest } }`; default and EAP sites removed.
- Debug: set `RADIUS_DEBUG=1` on the service for `freeradius -X` traces.

### 10.4 OpenVPN (`lab/openvpn/`)

- `server.conf`: `verify-client-cert none`, `username-as-common-name`, `auth-user-pass-verify /etc/openvpn/radius-verify.sh via-file`, `auth-gen-token 28800`, TLS ≥ 1.2, AES-GCM / ChaCha20 data ciphers, runs as `nobody`.
- `radius-verify.sh`: validates the username format, escapes values and calls `radclient` with `Calling-Station-Id` = client IP.
- PKI: EC P-256 lab CA created on first start (`easy-rsa`), CA certificate shared with clients through the `vpn-client-share` volume.
- Client profile for staff: `lab/vpn-client/client.conf` plus `static-challenge "Enter your authenticator code" 1` so the OpenVPN client asks for the code separately.

### 10.5 Test

```bash
cd lab
docker compose --profile vpn-test run --rm vpn-client                          # VPN_TEST_RESULT=PASS tunnel established
docker compose --profile vpn-test run --rm -e MODE=bad-otp vpn-client          # VPN_TEST_RESULT=PASS wrong OTP refused
docker compose exec -T openvpn sh -c 'printf "User-Name = \"svc.mfa-probe\"\nUser-Password = \"no-otp\"\n" | radclient freeradius:1812 auth "$RADIUS_SHARED_SECRET"'   # Access-Reject
```

| Test | Expected | Automated |
|---|---|---|
| Password + valid TOTP | Access-Accept; tunnel `10.8.0.x`, ping 10.8.0.1 | Checks 12, 13 |
| Wrong TOTP | Access-Reject / `AUTH_FAILED` | Checks 12, 13 |
| Password only | Access-Reject (`otp_missing`) | Check 12 |
| User without `vpn-users` | Access-Reject (`not_authorized_for_vpn`) | Manual (e.g. `f.dsouza`) |

---

## 11. Verification and evidence

```bash
python3 scripts/verify_mfa.py      # 18 checks; writes docs/evidence/verify_<UTC>.json and verify_latest.json
```

| Requirement | Check(s) |
|---|---|
| Baseline single-factor directory | 2 (+ `assess_baseline.py`) |
| SMS OTP / Email OTP | 4, 5, 7, 8, 9 |
| App-based TOTP | 6, 11, 12 |
| Biometrics | 9 |
| Hardware token | 10 |
| Backup codes | 11 |
| SSO across applications | 6, 6b |
| VPN / remote access | 12, 13 |
| Monitoring | 14–17 |
