# 03 — Implementation Plan

**Covers:** step-by-step roadmap, pilot test with virtual users, phased rollout across departments, and the user training and awareness programme.
**Builds on:** Assessment Report (01) and Solution Design (02).

---

## 1. Roles and responsibilities

| Role | Responsibility | Lab persona |
|---|---|---|
| Executive sponsor | Approves policy, budget (hardware keys, SMS), enforcement dates | a.mehta |
| Project lead / IAM owner | Plan, configuration, change control, go/no-go decisions | r.iyer |
| IAM engineer | Keycloak, directory federation, flows, SPI deployment | s.kumar |
| Network engineer | OpenVPN, FreeRADIUS, client profiles | s.kumar |
| SOC analyst | Wazuh rules, alert triage, IR drills | r.iyer |
| Service desk lead | Enrolment support, identity verification, lost-token SOP | (service desk) |
| Communications / HR | Announcements, training logistics, accessibility requests | m.rao |
| Data protection officer | GDPR/HIPAA review, records of processing | (DPO) |
| Department champions | One per department: first adopters, peer support | f.dsouza, p.nair, c.vendor's sponsor |

## 2. Step-by-step roadmap

| Step | Activity | Output | Lab artefact | Exit criterion |
|---|---|---|---|---|
| 1 | Baseline assessment and requirements | Assessment report, requirements | `scripts/assess_baseline.py`, doc 01 | Findings accepted by sponsor |
| 2 | Solution design and method selection | Design document | doc 02 | Design approved |
| 3 | Policies and compliance mapping | MFA policy, SOPs, GDPR/HIPAA checklists | doc 05 | DPO sign-off |
| 4 | Build the IdP and federate the directory | Realm `enterprise-realm`, LDAP read-only federation, group→role mapping | `lab/keycloak/realm/enterprise-realm.json` | All directory users visible in Keycloak |
| 5 | Configure the five MFA methods + backup codes | TOTP, WebAuthn, SMS/Email OTP SPI and bridge, recovery codes | doc 04 §3–8 | Verification checks 4–11 pass |
| 6 | Integrate SSO applications | OIDC clients, assurance checks in apps | doc 04 §9 | Checks 6 and 6b pass |
| 7 | Integrate VPN | OpenVPN → FreeRADIUS → bridge → Keycloak | doc 04 §10 | Checks 12 and 13 pass |
| 8 | Monitoring and IR readiness | Wazuh decoders/rules, playbooks, drill | doc 06, `simulate_ir_drill.py` | Drill passes, alerts triaged |
| 9 | Pilot (virtual users) | Pilot report, fixes | §3 | Pilot success criteria met |
| 10 | Training and communications | Materials, sessions, campaign | §5 | Material published before each wave |
| 11 | Phased rollout | Waves 1–5 | §4 | Per-wave exit criteria |
| 12 | Enforcement and legacy cutover | Single-factor paths removed, directory hardened | §4 wave 5 | Baseline probes B1–B4, B6 show CONTROL PRESENT |
| 13 | Operate and improve | Monthly usage report, quarterly drill, annual policy review | `mfa_usage_report.py` | KPIs in §6 |

## 3. Pilot test (virtual users)

### 3.1 Pilot cohort

The pilot uses the lab's virtual users, chosen so that every tier, method, access path and accessibility need is exercised:

| Virtual user | Department | Method under test | Access paths | Scenario focus |
|---|---|---|---|---|
| r.iyer | Executive / IT | Hardware key (YubiKey) | SSO, `/admin`, VPN | Privileged access at AAL3 |
| a.mehta | Executive | Biometrics (Windows Hello / Touch ID) | SSO | Travel, no codes |
| p.nair | Engineering | Biometrics + initial enrolment OTP | SSO, VPN | First-time enrolment |
| f.dsouza | Finance | TOTP app | SSO `/finance` | Payment approvals at AAL2 |
| k.shetty | Finance | TOTP app | VPN | Remote access |
| j.doe | General staff | SMS OTP (no smartphone) | SSO | Fallback tier |
| l.fernandes | General staff | Email OTP (screen reader) | SSO | Accessibility |
| c.vendor | Contractor | TOTP app on own phone | SSO, VPN | Third-party onboarding |
| svc.mfa-probe | Service account | TOTP (scripted) + backup codes | SSO, VPN | Automated regression |

In production the same profile is scaled to ~25 volunteers (≈ 2–3 per department) for 2 weeks.

### 3.2 Pilot procedure

1. **Day 0 — preparation:** deploy the lab (`./scripts/setup_lab.sh`), run `assess_baseline.py` to record the "before" state, brief champions.
2. **Days 1–3 — enrolment:** each pilot user signs in to `http://localhost:5000`, completes the initial OTP and registers their authenticator; record time to enrol and any helpdesk contact.
3. **Days 4–10 — daily use:** SSO across `corp-portal` and `hr-portal`, VPN connections for remote users, at least one "lost phone" exercise using backup codes and one fallback switch (SMS ↔ email).
4. **Day 11 — automated regression:** `python3 scripts/verify_mfa.py` (18 checks) and the IR drill `python3 scripts/simulate_ir_drill.py`.
5. **Days 12–14 — feedback and fixes:** survey (§3.4), defect triage, configuration changes, re-run verification.

### 3.3 Success metrics (go/no-go for rollout)

| Metric | Target | Measured by |
|---|---|---|
| Enrolment completed without helpdesk help | ≥ 95 % of pilot users | Enrolment log, survey |
| Median time to enrol | ≤ 5 minutes | Observation / survey |
| Sign-in success rate (MFA step) | ≥ 98 % | `mfa_usage_report.py` (LOGIN vs LOGIN_ERROR) |
| Helpdesk tickets per pilot user | ≤ 0.1 | Ticket system |
| Median extra time per sign-in due to MFA | ≤ 15 s | Survey / observation |
| Fallback (SMS/Email/backup code) share of sign-ins | ≤ 15 % outside the fallback tier | `mfa_usage_report.py` |
| Automated verification | 18/18 checks pass | `docs/evidence/verify_latest.json` |
| IR drill | Alert raised and account contained, attacker never signs in | Drill after-action report (06) |
| Accessibility | Screen-reader and no-smartphone users complete sign-in unaided | Assisted test sessions |
| User satisfaction | ≥ 4 / 5 average | Survey |

### 3.4 Feedback collection — pilot survey

1. Which method did you use? (biometrics / security key / authenticator app / SMS / email)
2. How easy was enrolment? (1 very hard … 5 very easy)
3. How many minutes did enrolment take?
4. How often were you asked for a second factor in a normal day? (once / 2–3 / more)
5. Did MFA ever stop you from working? If yes, describe what happened.
6. Did you use backup codes or switch between SMS and email? Was it clear how?
7. (VPN users) Did the VPN prompt for your code work first time? Were you re-prompted on reconnect?
8. (Assistive technology users) Did your screen reader / magnifier / switch device work on every page? Which page caused problems?
9. Were the error messages clear about what to do next?
10. Overall satisfaction (1–5) and one thing you would change.

Feedback is reviewed with champions in a 30-minute retrospective; every item is classified as configuration fix, documentation/training fix, or accepted limitation.

## 4. Phased rollout across departments

Order principle: highest risk and most technical users first, largest and least technical populations later, legacy shutdown last.

| Wave | Weeks | Population | Methods | Key activities | Exit criteria |
|---|---|---|---|---|---|
| **1 — IT administrators & Engineering** | 1–2 | `it-admins`, Engineering OU | Hardware keys (2 per admin), biometrics | Issue YubiKeys; enforce AAL3 on admin consoles; break-glass accounts sealed | 100 % of admins on WebAuthn; no admin sign-in at < AAL3 |
| **2 — Executives** | 3 | Executive OU | Biometrics + backup hardware key | Desk-side enrolment by IAM team ("white glove"), travel briefing | All executives enrolled; executive assistants trained on lost-device SOP |
| **3 — Remote / VPN users & Finance** | 4–5 | `vpn-users`, Finance OU | TOTP | Distribute OpenVPN profile with static-challenge prompt; enforce MFA on VPN; `/finance` requires AAL2 | VPN password-only access disabled; VPN failure rate < 2 % |
| **4 — General staff & fallback tier** | 6–8 | GeneralStaff OU (by site / time zone) | TOTP; SMS/Email OTP for the fallback tier | Drop-in clinics, accessibility appointments, fallback tier assignments by HR/IT | ≥ 98 % enrolled; accessibility requests resolved |
| **5 — Contractors & enforcement** | 9–10 | Contractors OU; everyone | TOTP | Contractor onboarding via sponsor; default-deny for untiered accounts; decommission `/legacy`; directory hardening (TLS required, no anonymous read, ppolicy) | Baseline probes B1–B4, B6 re-run show CONTROL PRESENT; zero single-factor sign-ins in `mfa_usage_report.py` |

**Per-wave routine:** announcement 2 weeks before, reminder 3 days before, training session in week 1 of the wave, grace period of 5 working days during which unenrolled users are redirected to enrolment, then enforcement. Each wave ends with `verify_mfa.py`, a review of the usage report and a go/no-go for the next wave.

### 4.1 Rollback

Per-tier rollback is a directory group change (move users to the fallback tier) or binding the previous browser flow in Keycloak; neither requires redeploying applications. VPN rollback is reverting the RADIUS site to the previous configuration. Rollback requires the project lead's approval and is logged as an admin event.

## 5. User training and awareness

### 5.1 Training sessions

| Audience | Format | Duration | Content |
|---|---|---|---|
| All staff | Live online session (recorded, captioned) + quick-start guide | 30 min | Why MFA; enrolment walkthrough; daily sign-in; backup codes; what to do if a phone is lost |
| Executives & assistants | Desk-side 1:1 | 20 min | Biometrics enrolment, second key, travel tips, reporting suspicious prompts |
| IT administrators | Workshop | 2 h | AAL3 admin access, break-glass procedure, Admin API containment, lost-token SOP, identity verification for resets |
| Service desk | Workshop + role play | 2 h | Identity verification script, never asking for codes, issuing temporary access, escalation to SOC |
| Remote / VPN users | Short video + guide | 15 min | VPN profile, entering the code at the challenge prompt |
| Contractors | Onboarding module via sponsor | 15 min | Own-device TOTP, access expiry, reporting |
| Users with accessibility needs | Individual appointment | 30 min | Choosing SMS or email, screen-reader walkthrough, backup arrangements |

### 5.2 Employee quick-start guide (handout)

1. Go to the Corp Portal and sign in with your usual username and password.
2. **First time only:** choose *Text message* or *Email* — enter the 6-digit code we send you. This proves it is really you before you set up your authenticator.
3. Set up your authenticator:
   - **Authenticator app:** install Microsoft Authenticator or Google Authenticator, scan the QR code, type the 6-digit code shown in the app.
   - **Fingerprint / face:** choose *This device* and confirm with Windows Hello or Touch ID.
   - **Security key:** insert your YubiKey, choose *Security key*, enter its PIN and touch it.
4. Create backup codes in *Account → Signing in → Recovery authentication codes*; print them or store them in your password manager.
5. Every day you approve the sign-in once; other applications open without asking again.
6. **Never share a code.** IT will never ask for it. If you get a code or prompt you did not request, do not use it — report it to the service desk immediately.
7. Lost your phone or key? Sign in with a backup code and remove the lost device in your account, then call the service desk.

### 5.3 Ongoing awareness campaign (first 12 months)

| Month | Theme | Channel | Call to action |
|---|---|---|---|
| 1 | "One sign-in, one approval" launch | Intranet banner, email from sponsor | Enrol before your wave date |
| 2 | Codes you did not ask for = attack in progress (OTP bombing / MFA fatigue) | Poster, Teams/Slack post | Report unexpected codes |
| 3 | Real-time phishing pages that steal codes | 5-min micro-learning | Check the address bar; prefer biometrics/keys |
| 4 | Back up before you need it | Email nudge to users without backup codes | Generate backup codes |
| 5 | SIM swap and number porting | Article | Add a carrier PIN to your mobile account |
| 6 | Phishing simulation including a fake MFA page | Simulation + feedback | Report, do not enter codes |
| 7 | Travelling with MFA | Pre-travel email | Carry a backup method |
| 8 | Helpdesk impersonation | Newsletter | IT never asks for codes |
| 9 | Contractors & third parties | Sponsor briefing | Confirm access end dates |
| 10 | Cybersecurity awareness month: results so far | All-hands slot | Celebrate adoption; share drill lessons |
| 11 | Upgrade to phishing-resistant | Offer of keys/biometrics to TOTP users | Volunteer for passkeys |
| 12 | Annual refresher | 15-min module | Complete and re-attest policy |

Campaign effectiveness is tracked through: report rate of unexpected codes, phishing-simulation submission rate, backup-code coverage, and fallback share from `mfa_usage_report.py`.

## 6. Operational KPIs after rollout

| KPI | Target | Source |
|---|---|---|
| Accounts enrolled in their tier's primary method | ≥ 98 % | Keycloak credentials report |
| Single-factor sign-ins | 0 | Usage report (LOGIN without `mfa_method`, excluding SSO cookie re-use) |
| MFA-related helpdesk tickets | < 3 % of users per month | Ticket system |
| OTP-bombing / repeated-MFA-failure alerts triaged within SLA | 100 % within 15 min | Wazuh + IR log |
| IR drill | Quarterly, passes | `simulate_ir_drill.py` reports |
