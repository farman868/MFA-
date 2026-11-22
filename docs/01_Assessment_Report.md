# 01 — Assessment Report

**Project:** Implementing a Robust Multi-Factor Authentication (MFA) System in an Enterprise Environment
**Organisation (simulated):** Enterprise Corp — multinational, directory `dc=corp,dc=enterprise,dc=local`
**Deliverable:** Assessment of current authentication mechanisms and stakeholder requirements
**Evidence:** `scripts/assess_baseline.py` → `docs/evidence/baseline_latest.json`

---

## 1. Executive summary

Enterprise Corp authenticates staff, executives and contractors with a **single factor — a static directory password** — for its intranet, line-of-business applications and remote access. The directory (OpenLDAP, standing in for Active Directory) accepts cleartext binds, exposes staff contact data to anonymous readers, applies no password or lockout policy, and nothing records or alerts on authentication activity.

Any one stolen, phished, guessed or re-used password therefore gives full access to that user's resources, including remote access from the internet, and the organisation would not notice. For a company that processes personal data of employees and customers (GDPR) and, in its healthcare business line, electronic protected health information (HIPAA), this is the highest-priority identity risk.

The assessment found **10 gaps (5 High, 4 Medium, 1 Low)** and gathered **42 requirements** from five stakeholder groups. It recommends a central identity provider that enforces a risk-tiered second factor (phishing-resistant WebAuthn for privileged users, authenticator apps for the general workforce, SMS/Email OTP only as an accessible fallback), integrated with SSO and the VPN and backed by authentication monitoring and an incident response process. Documents 02–06 design, plan, configure, govern and monitor that solution.

## 2. Scope and method

| Item | Detail |
|---|---|
| Environment | Docker lab in `lab/` reproducing Enterprise Corp's baseline: OpenLDAP directory with 5 organisational units and 10 staff accounts, a legacy intranet that authenticates directly against LDAP (`corp-portal` route `/legacy`), and the remote-access path |
| In scope | Directory service, application sign-in, remote access (VPN), administrative access, authentication logging and monitoring |
| Out of scope | Endpoint security, network segmentation, application authorisation logic |
| Method | (1) Configuration review of the directory and applications; (2) technical probes automated in `scripts/assess_baseline.py` (B1–B8); (3) stakeholder workshops represented by the personas in §6 |
| Rating | Likelihood × Impact on a 3-point scale (Low/Medium/High); risk = the higher-weighted combination in the matrix in §4 |

### 2.1 Baseline inventory

| Component | Baseline (before MFA) | Authentication | Logging |
|---|---|---|---|
| Directory (`openldap`) | `ldap://openldap:389`, simple bind, plaintext transport allowed, 5 OUs (Executive, Engineering, Finance, GeneralStaff, Contractors) | Password | None reviewed |
| Legacy intranet (`/legacy`) | Binds as the user directly against LDAP | Password only | None |
| Line-of-business apps | Each app checks the LDAP password itself (no SSO) | Password only, re-entered per app | Per-app, not centralised |
| Remote access VPN | OpenVPN, credentials checked against the directory | Password only | Gateway log, not monitored |
| Administration | Shared `cn=admin` directory account | Password only | None |

### 2.2 Directory population

| User | OU / role | Device situation | Relevance |
|---|---|---|---|
| a.mehta | Executive — CEO | Laptop with fingerprint/face sensor; travels | High-value target (whaling, AiTM phishing) |
| r.iyer | Executive — CISO / IAM admin | Hardware key holder | Privileged administrator |
| s.kumar | Engineering — platform engineer | Hardware key | Privileged, remote |
| p.nair | Engineering | Laptop biometrics | Remote |
| f.dsouza | Finance controller | Smartphone | Payment approvals |
| k.shetty | Finance analyst | Smartphone, remote | VPN user |
| j.doe | General staff — operations | **No corporate smartphone** | Needs SMS fallback |
| m.rao | General staff — HR | Smartphone, hybrid | VPN user, HR data |
| l.fernandes | General staff — support lead | **Screen-reader user (low vision)** | Needs accessible email OTP |
| c.vendor | Contractor (MSP) | Own smartphone | Third party, time-boxed |

## 3. Findings — gaps and vulnerabilities

Probe results (B1–B8) are produced by `python3 scripts/assess_baseline.py` against the running lab and saved to `docs/evidence/baseline_latest.json`; that file is the authoritative record of the observed results for this submission. Findings G8–G10 come from process and configuration review.

| ID | Gap / vulnerability | How it was assessed | Likelihood | Impact | Risk |
|---|---|---|---|---|---|
| **G1** | **Single-factor authentication** on the intranet, apps and VPN: a password alone grants access | B1 — sign-in to `/legacy` with password only | High | High | **High** |
| **G2** | **No lockout or throttling**: unlimited online guessing and credential stuffing | B2 — 20 wrong passwords, then the correct one still works | High | High | **High** |
| **G3** | **Cleartext directory binds**: passwords cross the network unencrypted on port 389 | B3 — `ldapwhoami -x -H ldap://` succeeds without StartTLS | Medium | High | **High** |
| **G4** | **Anonymous directory read**: names, emails and mobile numbers of all staff readable without credentials (personal data exposure, phishing reconnaissance) | B4 — anonymous `ldapsearch` | High | Medium | **Medium** |
| **G5** | Password hashes readable by the application bind account would allow offline cracking (probe B5 checks; record the observed result) | B5 — read-only account queries `userPassword` | Low | High | **Medium** |
| **G6** | **No directory password policy** (complexity, history, expiry, lockout) | B6 — `ppolicy` overlay not loaded | High | Medium | **Medium** |
| **G7** | **No authentication monitoring**: failed or anomalous sign-ins generate no alert and no central record | B7 — 22 legacy sign-in attempts produce no monitored event | High | High | **High** |
| **G8** | **No SSO**: users re-enter the same password in every application, multiplying exposure and phishing opportunities | Review | High | Medium | **Medium** |
| **G9** | **Privileged access uses the same single factor**; directory admin is a shared account | Review | Medium | High | **High** |
| **G10** | **No secure recovery or accessible alternatives**: password resets by phone with weak caller checks; nothing for staff without smartphones or with disabilities | Stakeholder input | Medium | Low | **Low** |

### 3.1 Attack scenarios enabled by the gaps

1. **Credential stuffing** — passwords leaked from another site are replayed against the VPN; with no lockout (G2) and no monitoring (G7) the attacker succeeds silently (G1).
2. **Phishing** — a fake intranet page collects passwords; because every app uses the same password (G8), one capture gives broad access.
3. **Network interception** — a compromised host on the office network reads passwords from cleartext LDAP binds (G3).
4. **Reconnaissance** — anonymous directory reads (G4) give the attacker every name, email and phone number for targeted phishing and SIM-swap attempts.
5. **Privilege takeover** — a guessed or phished administrator password (G9) gives control of the directory and every account.

## 4. Risk matrix

|  | **Low impact** | **Medium impact** | **High impact** |
|---|---|---|---|
| **High likelihood** | — | G4, G6, G8 | **G1, G2, G7** |
| **Medium likelihood** | G10 | — | **G3, G9** |
| **Low likelihood** | — | — | G5 |

## 5. Recommendations

| # | Recommendation | Addresses | Delivered in |
|---|---|---|---|
| R1 | Central identity provider (Keycloak, realm `enterprise-realm`) federating the existing directory | G1, G8, G9 | 02 §4.1, 04 §2 |
| R2 | Risk-tiered MFA: WebAuthn (biometrics / hardware key) for Executive & Engineering; TOTP app for Finance, General staff, Contractors; SMS / Email OTP fallback tier for users without smartphones or with accessibility needs; default deny for untiered accounts | G1, G9, G10 | 02 §3, 04 §3–8 |
| R3 | Single sign-on (OpenID Connect) for all web applications | G8 | 04 §9 |
| R4 | MFA on remote access: OpenVPN → RADIUS → IdP, password + TOTP | G1 | 04 §10 |
| R5 | Brute-force protection in the IdP, per-user OTP rate limits and lockout | G2 | 02 §5, 05 §2.6 |
| R6 | Authentication event logging into a SIEM (Wazuh) with detection rules and an incident response plan | G7 | 06 |
| R7 | Secure enrolment (OTP verification before an authenticator can be registered), backup codes and a lost-token procedure | G10 | 02 §6, 05 §3 |
| R8 | Directory hardening: require TLS (LDAPS/StartTLS), disable anonymous read, load a password policy, remove direct application binds | G3, G4, G5, G6 | 03 Phase 5 |
| R9 | Decommission the legacy single-factor intranet path after migration | G1 | 03 Phase 5 |

## 6. Requirements document

### 6.1 Stakeholder groups and input

Requirements were gathered through structured interviews and a workshop with one representative per stakeholder group (personas drawn from the directory population above).

| Group | Representatives | Main concerns raised |
|---|---|---|
| Executives | a.mehta (CEO) | Fast sign-in while travelling; protection against targeted phishing; no codes to type |
| Remote staff | k.shetty, m.rao, p.nair | Reliable VPN sign-in from home and hotels; no repeated prompts; works offline |
| IT administrators | r.iyer, s.kumar | Strongest protection for admin accounts; self-service enrolment to limit helpdesk load; central visibility; scriptable containment |
| Contractors | c.vendor | Use own phone; time-limited access; clear onboarding |
| Users with disabilities / without smartphones | l.fernandes (screen reader), j.doe (no smartphone) | A method that works with assistive technology, without a smartphone, without time pressure |

### 6.2 Functional requirements

| ID | Requirement | Priority | Source | Satisfied by |
|---|---|---|---|---|
| FR-01 | Every interactive sign-in to enterprise applications requires a second factor after the password | Must | IT admins | Flow `enterprise-browser` (02 §4.3) |
| FR-02 | Support SMS OTP for initial and fallback authentication | Must | No-smartphone users | `bridge-otp-authenticator` + mock SMS gateway |
| FR-03 | Support Email OTP for initial and fallback authentication | Must | Users with disabilities | `bridge-otp-authenticator` + Mailpit |
| FR-04 | Support authenticator apps (Google Authenticator, Microsoft Authenticator) | Must | General staff, contractors | TOTP policy HmacSHA1, 6 digits, 30 s |
| FR-05 | Support biometrics (fingerprint, facial recognition) through platform authenticators | Must | Executives | WebAuthn (platform) |
| FR-06 | Support hardware tokens (YubiKey) | Must | IT admins | WebAuthn/FIDO2 (roaming) |
| FR-07 | Single sign-on: authenticate once to reach multiple applications | Must | All | OIDC clients `corp-portal`, `hr-portal` |
| FR-08 | VPN / remote access requires MFA | Must | IT admins | OpenVPN → FreeRADIUS → bridge → Keycloak |
| FR-09 | Users enrol and manage their own authenticators | Should | IT admins | Keycloak account console |
| FR-10 | Backup codes for users who lose their authenticator | Must | All | Recovery authentication codes |
| FR-11 | Integrate with the existing directory without migrating passwords | Must | IT admins | LDAP user federation (read-only) |
| FR-12 | Assign the MFA method by role/department automatically | Should | IT admins | LDAP groups → realm roles → conditional flows |
| FR-13 | Applications can see which method and assurance level was used | Should | Application owners | `mfa_method` and `aal` token claims |
| FR-14 | Administrators can revoke sessions and lock accounts centrally | Must | IT admins | Keycloak Admin API, bridge `/admin/lock` |

### 6.3 Security requirements

| ID | Requirement | Priority | Source |
|---|---|---|---|
| SR-01 | Privileged users (Executive, Engineering, IT admins) use phishing-resistant MFA (WebAuthn) | Must | IT admins, Executives |
| SR-02 | Accounts without an assigned MFA tier are denied | Must | IT admins |
| SR-03 | A stolen password alone must not allow registering a new authenticator | Must | IT admins |
| SR-04 | OTPs are random, single-use, expire within 5 minutes, limited to 5 attempts, and stored only as keyed hashes | Must | IT admins |
| SR-05 | OTP requests are rate-limited per user (anti OTP bombing) | Must | IT admins |
| SR-06 | Repeated failed sign-ins lock the account temporarily | Must | IT admins |
| SR-07 | Authentication and administrative events are logged centrally and monitored with alerting | Must | IT admins, compliance |
| SR-08 | Sensitive areas (finance approvals, administration) enforce a minimum assurance level | Should | Finance, IT admins |
| SR-09 | Secrets (client secrets, RADIUS secret, OTP keys) are not hard-coded and are generated per deployment | Must | IT admins |
| SR-10 | Biometric data never leaves the user's device | Must | Executives, compliance |

### 6.4 Usability requirements

| ID | Requirement | Priority | Source |
|---|---|---|---|
| UX-01 | No more than one MFA prompt per SSO session (8–10 h working day) | Must | All |
| UX-02 | Executives sign in with a touch/glance, no codes | Should | Executives |
| UX-03 | VPN works with any OpenVPN client using the standard challenge prompt, without re-prompting on reconnect | Must | Remote staff |
| UX-04 | Clear, plain-language error messages that say what to do next | Must | All |
| UX-05 | Self-service recovery with backup codes before contacting the helpdesk | Should | IT admins |
| UX-06 | TOTP works offline (no data connection needed) | Must | Remote staff |

### 6.5 Accessibility requirements

| ID | Requirement | Priority | Source |
|---|---|---|---|
| AC-01 | A second-factor option that does not require a smartphone | Must | j.doe |
| AC-02 | All MFA pages operable by keyboard and screen reader (labelled fields, real buttons, announced errors) | Must | l.fernandes |
| AC-03 | No time limit shorter than 5 minutes for entering a code, and a "send a new code" option | Must | l.fernandes |
| AC-04 | No CAPTCHA or puzzle-based challenges | Must | l.fernandes |
| AC-05 | One-time-code fields support OS autofill (`autocomplete="one-time-code"`) and numeric keypads | Should | All |
| AC-06 | Alternative arrangements documented for users who cannot use any standard factor | Must | Users with disabilities |

### 6.6 Compliance and contractor requirements

| ID | Requirement | Priority | Source |
|---|---|---|---|
| CR-01 | Authentication controls support GDPR Art. 32 security of processing and data protection by design (Art. 25) | Must | Compliance |
| CR-02 | Person or entity authentication for ePHI systems per HIPAA 45 CFR §164.312(d) | Must | Compliance |
| CR-03 | Audit logs retained and reviewable (HIPAA §164.312(b)) | Must | Compliance |
| CR-04 | Contractors receive time-boxed access, removed at contract end | Must | IT admins |
| CR-05 | Personal data used for MFA (phone, email) limited to what is necessary | Must | Compliance |
| CR-06 | Contractors use their own device only with an authenticator app, never SMS | Should | IT admins |

### 6.7 Constraints and assumptions

- The existing directory remains the source of truth for users and passwords during and after the rollout (read-only federation).
- No paid SaaS: SMS delivery is simulated by a mock gateway in the lab; production uses a contracted SMS provider.
- Not every employee has a corporate smartphone; some have assistive-technology needs.
- Budget allows hardware keys only for privileged users (≈ 10 % of staff).

## 7. Reproducing the evidence

```bash
./scripts/setup_lab.sh --no-verify
python3 scripts/assess_baseline.py        # writes docs/evidence/baseline_latest.json
```

The script records each probe as **GAP** or **CONTROL PRESENT** with the command output that justifies it. If a probe's observed result differs from the expectation in §3 (for example B5), the evidence file is correct and §3 should be updated to match it before submission.
