# 05 — Security Policies and Compliance Documentation

**Contents:** Part A — Enterprise MFA Policy. Part B — Standard Operating Procedures (enrolment, fallback, lost-token recovery, access removal, break-glass). Part C — Compliance checklists and guidelines for **GDPR** and **HIPAA**.

| Document control | |
|---|---|
| Owner | Chief Information Security Officer (r.iyer) |
| Approver | Executive sponsor (a.mehta); Data Protection Officer |
| Version / status | 1.0 — approved for rollout |
| Review | Annually, after any MFA-related incident, or when the regulations below change |
| Applies to | All Enterprise Corp entities, employees, executives, contractors and service accounts |

> The compliance mappings in Part C are guidance for this project and are not legal advice. Confirm interpretations with the organisation's legal counsel and Data Protection Officer.

---

# Part A — Enterprise MFA Policy

## A.1 Purpose

To protect enterprise resources and the personal and health data they hold from unauthorised access by requiring multi-factor authentication (MFA) wherever a user or administrator signs in, and to define how authenticators are issued, used, recovered and revoked.

## A.2 Scope

1. **People:** employees, executives, contractors, temporary staff and anyone with an account in the corporate directory.
2. **Systems:** every application integrated with the identity provider (Keycloak realm `enterprise-realm`) through SSO; remote access (VPN); administrative consoles (identity provider, directory, servers, cloud); any system storing personal data or electronic protected health information (ePHI).
3. **Exclusions:** none by default. Service accounts that cannot perform MFA require a documented exception (A.9).

## A.3 Policy statements

1. **MFA everywhere.** Interactive sign-in to in-scope systems requires a password plus an approved second factor. Accounts not assigned to an MFA tier are denied access.
2. **Risk-tiered authenticators.** The required authenticator depends on the user's role:

| Tier (directory group) | Who | Required authenticator | Minimum assurance |
|---|---|---|---|
| `mfa-tier-webauthn` | Executives, Engineering, IT administrators, anyone with privileged access | Phishing-resistant: platform biometrics (Windows Hello, Touch ID) or FIDO2 hardware key | AAL3 |
| `mfa-tier-totp` | Finance, General staff with a smartphone, Contractors | Authenticator app (Microsoft Authenticator, Google Authenticator) | AAL2 |
| `mfa-tier-otp-fallback` | Staff without a smartphone or with an accessibility need, approved by IT/HR | SMS OTP or Email OTP | AAL2 (SMS) / AAL1 (Email) |

3. **Privileged access** (identity provider, directory, infrastructure admin) requires AAL3 and membership in `it-admins`; backup codes do not grant privileged access.
4. **Remote access** (VPN) requires password + authenticator-app code and membership in `vpn-users`.
5. **Sensitive data:** systems processing financial approvals, ePHI or special-category personal data require at least AAL2; Email OTP (AAL1) is not sufficient.
6. **Single sign-on** is the standard integration pattern; applications must not implement their own password checks against the directory.
7. **Secrets are personal.** Users must never share codes, backup codes, authenticators or approve sign-ins they did not start. IT staff must never ask for them.
8. **Session limits:** SSO idle timeout 30 minutes, maximum 10 hours; VPN session token maximum 8 hours.
9. **Account protection:** after 10 failed sign-ins the account is locked temporarily (increasing to 15 minutes); OTP requests are limited to 3 per minute and 10 per hour per user.
10. **Monitoring:** authentication and administrative events are logged centrally and monitored (document 06). Logs are retained for at least 6 years for systems in HIPAA scope and 1 year elsewhere, then deleted.

## A.4 Approved authenticators

| Authenticator | Approved models / apps | Conditions |
|---|---|---|
| Platform biometrics | Windows Hello (face/fingerprint), Apple Touch ID / Face ID on managed devices | Device screen lock required; biometric data never leaves the device |
| Hardware token | FIDO2 security keys from the approved list (e.g. YubiKey 5 series) | PIN set; two keys per privileged user; issued and recorded by IT |
| Authenticator app | Microsoft Authenticator, Google Authenticator (or another RFC 6238 app approved by IT) | Device screen lock required; cloud backup of the app allowed only with the account protected by MFA |
| SMS OTP | Any mobile phone number registered in the directory | Fallback tier and initial verification only; carrier account PIN recommended |
| Email OTP | Corporate mailbox registered in the directory | Fallback tier and initial verification only; not valid for AAL2+ resources |
| Backup codes | Keycloak recovery authentication codes (12, single use) | Stored offline or in an approved password manager |

Not approved: push-approval apps without number matching, voice calls, security questions, personal email addresses.

## A.5 Roles and responsibilities

| Role | Responsibilities |
|---|---|
| CISO | Owns this policy, approves exceptions, reports compliance |
| IAM team | Configures the IdP, tiers and flows; issues hardware keys; performs resets per SOP |
| Service desk | Verifies identity before any MFA reset; never asks for codes; escalates suspected attacks to the SOC |
| SOC | Monitors alerts, runs incident response, performs containment |
| Managers / contract sponsors | Approve tier assignments and contractor access; trigger access removal |
| HR | Joiner/mover/leaver events; accessibility accommodation requests |
| Users | Enrol, protect authenticators and backup codes, report loss or unexpected prompts immediately |
| DPO | Records of processing, privacy reviews, breach notification decisions |

## A.6 Enrolment

- Users enrol at first sign-in. Before an authenticator can be registered, the user must pass an SMS or Email OTP sent to the contact details already in the directory (so a stolen password alone cannot enrol an attacker's device).
- Privileged users enrol hardware keys in person with the IAM team, which records serial numbers.
- Users create backup codes within 7 days of enrolment.

## A.7 Fallback authentication

- SMS/Email OTP is permanent for the fallback tier and temporary for others (lost device: max 7 days, approved by the service desk per SOP B.3).
- Placement in the fallback tier requires a documented reason (no corporate smartphone, accessibility need) and is reviewed every 6 months.

## A.8 Lost, stolen or compromised authenticators

- Report immediately (target: within 1 hour of discovery) to the service desk or SOC.
- Revocation SLA: authenticator removed and sessions revoked within **1 hour** of the report (15 minutes for privileged users).
- See SOP B.3.

## A.9 Exceptions

Exceptions (e.g. a service account that cannot do MFA, a user who cannot use any listed authenticator) require a written request, compensating controls (network restriction, short-lived credentials, enhanced monitoring), CISO approval, and expire after a maximum of 6 months.

## A.10 Emergency (break-glass) access

- Two break-glass administrator accounts in the identity provider's master realm, each protected by a dedicated hardware key stored in a sealed safe, password split between two officers.
- Use only when normal administrator access is impossible; every use triggers an alert, is reviewed within 24 hours, and the credentials are rotated afterwards.

## A.11 Compliance and enforcement

Compliance is measured through the MFA usage report and quarterly incident-response drills. Violations (sharing codes, bypassing MFA) are handled under the disciplinary policy; contractor violations under the contract.

---

# Part B — Standard Operating Procedures

## B.1 SOP — Enrolment (new joiner / first sign-in)

| Step | Actor | Action | System evidence |
|---|---|---|---|
| 1 | HR | Creates the user in the directory with department, mobile number, email; adds to the correct tier and `vpn-users` if needed | Directory entry and group membership |
| 2 | IAM | Confirms LDAP sync (≤ 5 min) | User visible in Keycloak with tier role |
| 3 | User | Signs in to the portal with the initial password | — |
| 4 | User | Passes the initial SMS/Email OTP | Bridge `SEND_OTP`, `OTP_VERIFIED` |
| 5 | User | Registers the tier authenticator (QR for TOTP, biometrics or key for WebAuthn) | Keycloak `UPDATE_CREDENTIAL` / `UPDATE_TOTP` event |
| 6 | User | Generates and stores backup codes | Credential `recovery-authn-codes` |
| 7 | User | Completes the 30-min training and acknowledges this policy | Training record |

## B.2 SOP — Using fallback authentication

1. User selects *Try another way* (backup code) or *Use a different method* (SMS ↔ Email for the fallback tier).
2. If the user has no working method, they contact the service desk, which verifies identity using **two** of: callback to the number in the HR system (not one given on the call), manager confirmation via a separate channel, video call with ID check.
3. Service desk grants a temporary fallback tier membership (max 7 days) with ticket reference; never reads codes to the user.
4. The SOC reviews all temporary fallback grants weekly.

## B.3 SOP — Lost, stolen or compromised authenticator (lost-token recovery)

| Step | Time target | Actor | Action |
|---|---|---|---|
| 1 | Immediately | User | Reports loss to service desk / SOC |
| 2 | ≤ 15 min | Service desk | Verifies identity (B.2 step 2) and opens a ticket |
| 3 | ≤ 1 h (15 min privileged) | IAM | Keycloak Admin → *Users* → user → *Credentials*: delete the lost authenticator; *Sessions* → **Sign out all sessions** (Admin API `POST /users/{id}/logout`) |
| 4 | ≤ 1 h | IAM | If theft or compromise suspected: disable account, lock the OTP channel (`POST /admin/lock` on mfa-otp-bridge), force directory password reset; notify SOC (IR playbook 06 §4.4) |
| 5 | Same day | User | Signs in with a backup code or temporary fallback, registers a new authenticator, generates new backup codes |
| 6 | ≤ 24 h | SOC | Reviews sign-in events since the time of loss for misuse |
| 7 | Close | IAM | Hardware keys: record serial as lost; issue replacement; close ticket |

## B.4 SOP — Access removal (leaver / contractor end)

1. HR or contract sponsor triggers the leaver event; directory account disabled and removed from tier and `vpn-users` groups.
2. IAM revokes Keycloak sessions and deletes MFA credentials within 24 hours (1 hour for involuntary leavers and privileged users).
3. Hardware keys returned and reset; contractor access must have an end date at creation and is reviewed monthly.

## B.5 SOP — Break-glass use

1. Two officers retrieve the sealed key and password halves; log time, reason and approver.
2. Perform only the emergency task; record actions.
3. Within 24 h: SOC reviews admin events; rotate password, re-seal key, report to the CISO.

---

# Part C — Compliance checklists and guidelines

Legend: **Implemented** = enforced by the lab configuration and evidenced; **Procedural** = met by Part A/B; **Partial** = further action needed (see notes).

## C.1 GDPR (Regulation (EU) 2016/679)

GDPR requires security appropriate to the risk for personal data, including the data of employees and customers held in the systems protected by MFA, and it also governs the personal data the MFA system itself uses (phone numbers, email addresses, authentication logs).

| # | GDPR provision | Requirement (summary) | MFA control | Evidence | Status |
|---|---|---|---|---|---|
| G-1 | Art. 5(1)(f) Integrity and confidentiality | Protect personal data against unauthorised access | MFA on all sign-ins, default deny, VPN MFA | `verify_mfa.py` checks 6–13 | Implemented |
| G-2 | Art. 32(1)(b) Security of processing | Ensure ongoing confidentiality, integrity, availability and resilience | Phishing-resistant MFA for privileged users; brute-force and OTP rate limits; backup codes and fallback keep access available | Realm config; checks 9–11 | Implemented |
| G-3 | Art. 32(1)(d) | Regularly test, assess and evaluate the effectiveness of measures | Automated verification, baseline assessment, quarterly IR drill | `docs/evidence/` reports | Implemented |
| G-4 | Art. 32(4) | Persons with access act only on instructions | Role-based tiers, `it-admins` + AAL3 for admin, training and policy acknowledgement | Flow `enterprise-browser`; doc 03 §5 | Implemented / Procedural |
| G-5 | Art. 25 Data protection by design and by default | Build data protection into the system; minimise data | OTPs stored only as HMAC for 5 min; destinations masked in logs; no biometric templates leave devices (WebAuthn); read-only directory federation | `lab/mfa-otp-bridge/app/main.py`; doc 02 §8 | Implemented |
| G-6 | Art. 5(1)(c) Data minimisation | Only necessary personal data | MFA reuses existing mobile/email; no new identifiers collected | Directory mappers | Implemented |
| G-7 | Art. 5(1)(e) Storage limitation | Keep data no longer than necessary | Log retention defined (A.3.10); Keycloak stored events expire after 7 days in the lab | Realm `eventsExpiration` | Partial — configure SIEM retention/deletion in production |
| G-8 | Art. 6 Lawful basis / Art. 13 Information | Processing of phone/email/logs for security must have a lawful basis and be explained | Legitimate interest (network and information security, Recital 49) documented; employee privacy notice updated | Privacy notice | Procedural |
| G-9 | Art. 9 Special-category data | Biometric data for unique identification needs an Art. 9 condition | Design avoids processing: matching happens on the user's device; server holds only a public key | Doc 02 §8 | Implemented (by design) |
| G-10 | Art. 30 Records of processing | Record processing activities | Add "MFA and authentication logging" entry: purposes, categories (staff identifiers, phone, email, IP, timestamps), recipients (SMS provider), retention | RoPA | Procedural |
| G-11 | Art. 28 Processors | Contracts with processors | Data processing agreement with the SMS provider and any hosted SIEM | Contracts | Procedural |
| G-12 | Art. 35 DPIA | Assess high-risk processing | DPIA screening for authentication monitoring of employees; full DPIA if monitoring is systematic/large-scale | DPIA record | Procedural |
| G-13 | Art. 33 Breach notification to authority | Notify within 72 hours of awareness | IR plan includes DPO decision point and 72-h clock | Doc 06 §4.7 | Implemented (plan) |
| G-14 | Art. 34 Communication to data subjects | Inform individuals of high-risk breaches | IR plan communication step | Doc 06 §4.7 | Procedural |
| G-15 | Art. 15–17 Data subject rights | Access/erasure requests may include MFA data and logs | Process to export/delete a user's credentials and events (Keycloak Admin API) on request, balanced against security retention | SOP | Procedural |

**GDPR guidelines for operating the MFA system**

1. Mask phone numbers and email addresses in logs and screens (implemented in the bridge and OTP pages).
2. Never log OTP values, backup codes or TOTP seeds.
3. Restrict access to authentication logs to the SOC and IAM team; log access to the SIEM.
4. If an SMS provider outside the EEA is used, put transfer safeguards in place (Chapter V).
5. Review fallback-tier membership (which requires processing phone numbers) every 6 months.

## C.2 HIPAA Security Rule (45 CFR Part 164, Subpart C)

Applies to systems that create, receive, maintain or transmit electronic protected health information (ePHI) — for Enterprise Corp, its healthcare business line. (R) = required, (A) = addressable.

| # | Standard / implementation specification | Requirement (summary) | MFA control | Evidence | Status |
|---|---|---|---|---|---|
| H-1 | §164.312(d) Person or entity authentication (R) | Verify that a person seeking access to ePHI is the one claimed | Password + second factor for every user; ePHI applications require ≥ AAL2 | Checks 6–11; policy A.3.5 | Implemented |
| H-2 | §164.312(a)(1) Access control | Allow access only to authorised persons/software | SSO with role claims; tier and role enforcement; default deny | Flow `tier-none-deny`; portal assurance checks | Implemented |
| H-3 | §164.312(a)(2)(i) Unique user identification (R) | Unique name/number per user | Directory `uid` + Keycloak user ID; no shared accounts (legacy shared admin removed) | Directory, realm | Implemented |
| H-4 | §164.312(a)(2)(ii) Emergency access procedure (R) | Obtain ePHI in an emergency | Break-glass accounts (A.10, B.5) | SOP | Procedural |
| H-5 | §164.312(a)(2)(iii) Automatic logoff (A) | Terminate sessions after inactivity | SSO idle 30 min / max 10 h; app session 30 min | Realm `ssoSessionIdleTimeout` | Implemented |
| H-6 | §164.312(b) Audit controls (R) | Record and examine activity | Keycloak user + admin events, bridge events, Wazuh collection | Doc 06; check 14 | Implemented |
| H-7 | §164.312(c)(1) Integrity | Protect ePHI from improper alteration | MFA protects accounts that can modify ePHI; admin changes logged (rules 100505–100508) | Rules | Implemented (supporting) |
| H-8 | §164.312(e)(1) Transmission security | Guard against unauthorised access in transit | VPN with TLS ≥ 1.2; production: TLS for IdP, LDAPS (lab uses HTTP on localhost) | Doc 01 G3; doc 03 wave 5 | Partial — enforce TLS in production |
| H-9 | §164.308(a)(1)(ii)(D) Information system activity review (R) | Regularly review audit logs, access reports | Monthly `mfa_usage_report.py`; alert triage | Usage reports | Implemented |
| H-10 | §164.308(a)(3)(ii)(C) Termination procedures (A) | End access when employment ends | Leaver SOP B.4 | SOP | Procedural |
| H-11 | §164.308(a)(4) Information access management | Authorise access by role | Tier and role groups managed in the directory, approved by managers | Directory groups | Implemented / Procedural |
| H-12 | §164.308(a)(5)(ii)(C) Log-in monitoring (A) | Monitor log-in attempts and report discrepancies | Wazuh rules 100502–100533 (failures, brute force, OTP bombing, VPN) | Doc 06; IR drill | Implemented |
| H-13 | §164.308(a)(5)(ii)(D) Password management (A) | Procedures for creating, changing, safeguarding passwords | Passwords supplemented by MFA; directory password policy (wave 5); never share codes | Policy A.3.7 | Partial — directory ppolicy pending (G6) |
| H-14 | §164.308(a)(5)(i) Security awareness and training | Training for all workforce members | Training and 12-month campaign | Doc 03 §5 | Procedural |
| H-15 | §164.308(a)(6) Security incident procedures (R) | Identify, respond to, mitigate and document incidents | IR plan and playbooks; drill with documented outcome | Doc 06 | Implemented |
| H-16 | §164.308(a)(7)(ii)(C) Emergency mode operation (R) | Continue critical processes in emergencies | Break-glass; fallback methods; backup codes | Policy A.10 | Procedural |
| H-17 | §164.308(a)(8) Evaluation | Periodic technical and non-technical evaluation | Verification script, quarterly drill, annual policy review | Evidence folder | Implemented |
| H-18 | §164.308(b)(1) Business associate contracts | Assurances from vendors handling ePHI | BAAs with any hosted IdP/SIEM/SMS vendor that could access ePHI | Contracts | Procedural |
| H-19 | §164.316(b)(2)(i) Documentation retention (R) | Keep policies and records for 6 years | Policy, SOP records, drill reports retained 6 years | Document control | Procedural |
| H-20 | §164.404–410 Breach notification rule | Notify individuals without unreasonable delay and within 60 days of discovery; HHS; media if > 500 residents of a state | IR plan notification step | Doc 06 §4.7 | Implemented (plan) |

**HIPAA guidelines for operating the MFA system**

1. Tag applications that handle ePHI and require AAL2 or higher for them (portal pattern `require_assurance("AAL2")`).
2. Keep authentication and audit logs for ePHI systems for at least 6 years (documentation retention practice), access-controlled.
3. Use the break-glass procedure, not shared accounts, for emergency access to ePHI.
4. Review log-in monitoring alerts daily and document the review.
5. Before production, close the *Partial* items: TLS for all IdP and directory traffic (H-8), directory password policy (H-13).

## C.3 Consolidated checklist (for audits)

| ✔ | Control | GDPR | HIPAA |
|---|---|---|---|
| ☐ | MFA enforced on all interactive sign-ins, untiered accounts denied | Art. 32 | §164.312(d) |
| ☐ | Privileged access requires phishing-resistant MFA | Art. 32 | §164.312(a)(1) |
| ☐ | VPN requires MFA | Art. 32 | §164.312(e)(1) |
| ☐ | Unique accounts, no shared admin accounts | Art. 32 | §164.312(a)(2)(i) |
| ☐ | Session timeouts configured | Art. 32 | §164.312(a)(2)(iii) |
| ☐ | Authentication and admin events logged, monitored, reviewed monthly | Art. 32(1)(d) | §164.312(b), §164.308(a)(1)(ii)(D), (a)(5)(ii)(C) |
| ☐ | Incident response plan tested in the last quarter | Art. 32(1)(d), 33 | §164.308(a)(6) |
| ☐ | Lost-token and leaver procedures followed within SLA | Art. 32 | §164.308(a)(3)(ii)(C) |
| ☐ | Break-glass procedure documented and tested | Art. 32(1)(c) | §164.312(a)(2)(ii) |
| ☐ | MFA data minimised, OTPs not stored, biometrics on device | Art. 5, 25 | — |
| ☐ | Records of processing / DPIA screening updated | Art. 30, 35 | — |
| ☐ | Processor / business associate agreements in place (SMS, SIEM) | Art. 28 | §164.308(b)(1) |
| ☐ | Workforce trained and policy acknowledged | Art. 32(4) | §164.308(a)(5)(i) |
| ☐ | Policies and evidence retained (6 years for HIPAA scope) | Art. 5(2) accountability | §164.316(b)(2)(i) |
