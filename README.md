# Single Sign-On and Access Control with Keycloak

![Keycloak](https://img.shields.io/badge/Keycloak-26-blue) ![Level](https://img.shields.io/badge/Level-Beginner%20to%20Intermediate-yellow) ![Focus](https://img.shields.io/badge/Focus-IAM%20%7C%20SSO%20%7C%20OIDC-orange)

## Overview

**Scenario:** Northwind Traders is replacing scattered application logins with single sign-on (SSO). As the IAM engineer, I built the company's identity realm from scratch in **Keycloak**, secured it to an auditor's baseline, connected an application with **OpenID Connect**, and ran the full employee lifecycle: onboard, grant access, enforce MFA, detect an attack, and offboard.

The concepts used here (realms, clients, roles, groups, OIDC tokens, MFA, brute-force protection) are the same ones found in Okta, Microsoft Entra ID, and Ping.

## Skills Demonstrated

- Realm and tenant design
- Password and account lockout policy
- Role-based access control (RBAC) with groups
- Joiner-mover-leaver identity lifecycle
- OpenID Connect clients and flows
- JWT analysis and token introspection
- Audience restriction
- Service accounts (machine identities)
- TOTP multi-factor authentication
- Identity threat detection
- Access reviews and audit evidence

## Environment

| Component | Value |
|---|---|
| Identity provider | Keycloak 26 |
| Admin console | `http://172.18.0.3:8080/admin/` |
| Realm | `northwind` |
| Application (client) | `expense-app` |
| Tools | Firefox, curl, jq, Python 3 |

> **Note:** The lab environment resets between sessions, so this lab was completed across more than one session. That is why a few screenshots show different terminal hostnames, and why one early screenshot shows the group as `finance` (lowercase) while the final build and tokens use `Finance`.

---

## Task 0 – Connect to the Identity Server

Signed in to the Keycloak admin console with the bootstrap administrator account.

![Admin login](shot-32.png)

Opened a terminal and saved the server address in a variable for later tasks:

```bash
export KC=http://172.18.0.3:8080
```

![Terminal setup](shot-33.png)

---

## Task 1 – Create a Realm for the Company

A **realm** is an isolated identity space with its own users, applications, and security rules. The built-in `master` realm exists only to administer Keycloak itself. Putting employees there would mix platform admins with ordinary users, which is a common audit finding.

Created the `northwind` realm and did all further work inside it.

![Create realm](shot-34.png)

---

## Task 2 – Set the Authentication Security Baseline

### Password policy

| Policy | Value |
|---|---|
| Minimum Length | 12 |
| Uppercase Characters | 1 |
| Digits | 1 |
| Special Characters | 1 |
| Not Username | On |
| Not Recently Used | 3 |

![Password policy](shot-35.png)

### Brute-force detection

Set **Brute Force Mode** to *Lockout temporarily* with **Max login failures** of 5.

![Brute force detection](shot-36.png)

### Audit logging

Turned on **Save events** for both user events and admin events.

![User events on](shot-17.png)
![Admin events on](shot-18.png)

**Why it matters:** NIST SP 800-63B, CIS Controls v8 (Control 6), and most SOC 2 audits ask for exactly these three things: strong credentials, protection from password guessing, and an audit trail of who did what.

---

## Task 3 – Design Role-Based Access Control

The design principle: **grant access to roles, put roles on groups, and put people in groups.** Permissions are never assigned to individuals one by one, which is how permission creep starts.

### Roles

| Role | Purpose |
|---|---|
| `employee` | Everyone at Northwind |
| `finance-approver` | Can approve expense reports |
| `soc-analyst` | Can view security alerts |
| `it-admin` | Can administer internal systems |

![Realm roles](shot-19.png)

### Groups and role mappings

| Group | Roles |
|---|---|
| Finance | `employee`, `finance-approver` |
| Security Operations | `employee`, `soc-analyst` |
| IT | `employee`, `it-admin` |

![Groups](shot-20.png)
![IT role mapping](shot-21.png)
![Security Operations role mapping](shot-22.png)
![Finance role mapping](shot-23.png)

**Checkpoint:** Because roles live on groups rather than on people, moving someone from Finance to IT is a single change: swap their group membership, and every role they need (and lose) follows automatically.

---

## Task 4 – Onboard Employees (Joiners)

### alice (Finance)

Created `alice` (Alice Nguyen, `alice@northwind.test`) with email verified and joined her to the Finance group.

![Create alice](shot-24.png)

**Testing the password policy:** I first tried the weak password `password123`.

![Weak password attempt](shot-26.png)

Keycloak rejected it and named the failed rule:

![Password policy rejection](shot-25.png)

> `password123` also breaks the length and uppercase rules, but Keycloak reports the first rule it hits (special characters here). This proves the Task 2 policy is enforced.

Then set the temporary password `Welcome-2026-Tmp!` with **Temporary** on.

### sam (Security Operations)

Created `sam` (Sam Okafor) in Security Operations with the same temporary password. Because sam holds a privileged role, I added **Configure OTP** as a required user action so he must enroll MFA at his next sign-in.

![sam required actions](shot-27.png)

**Why a temporary password?** The helpdesk should never know a user's real password. The user must replace the temporary one at first login.

---

## Task 5 – Register an Application with OpenID Connect

Registered Northwind's expense app as an OIDC client, `expense-app`.

| Setting | Value | Why |
|---|---|---|
| Client authentication | On | Confidential client with a secret, correct for a server-side app |
| Standard flow | On | Browser redirect login used by real apps |
| Direct access grants | On | Lets the terminal request tokens for study only |
| Service account roles | On | Enables machine-to-machine tokens (Task 8) |
| Valid redirect URIs | `http://localhost:3000/*` | Only these URLs may receive login responses |

![Capability config](shot-29.png)
![Redirect URIs](shot-28.png)

Copied the client secret from the **Credentials** tab into a terminal variable (`export SECRET='...'`). The secret is masked in the screenshot.

![Client credentials](shot-30.png)

Added a **Group Membership** mapper named `groups` (Full group path off) so group names appear in tokens.

![Groups mapper](shot-31.png)

> **About Direct access grants:** this flow sends a username and password straight to Keycloak and was enabled only to study tokens from the terminal. Real applications use the Standard flow with PKCE so the app never sees the password.

---

## Task 6 – First Login and Reading a Token

### Forced password change

Signed in to the account console as alice with the temporary password. Keycloak forced a password change before activating the account.

![alice forced password update](shot-1.png)

### Requesting tokens

Requested tokens as `expense-app` using alice's credentials. The response included an `access_token`, `id_token`, and `refresh_token`, with `expires_in: 300`. Access tokens are short-lived on purpose.

![Token response](shot-2.png)

### Decoding the access token

A JWT is three base64url parts (header, payload, signature). I used a small helper to decode the payload:

```bash
jwt() { jq -R 'split(".") | .[1] | gsub("-";"+") | gsub("_";"/") | @base64d | fromjson'; }
echo "$TOKEN" | jwt
```

![Decoded claims part 1](shot-3.png)
![Decoded claims part 2](shot-4.png)

| Claim | Value observed | Meaning |
|---|---|---|
| `iss` | `http://172.18.0.3:8080/realms/northwind` | Who issued the token (my realm) |
| `sub` | `fbf69bc1-c4c5-4319-84b1-6a5b65c90525` | alice's unique, permanent user ID (matches her ID in the admin console) |
| `azp` | `expense-app` | The client that requested the token |
| `iat` / `exp` | `1790623613` / `1790623913` | Issued and expiry times in Unix seconds, exactly 300 seconds apart |
| `realm_access.roles` | includes `finance-approver`, `employee` | Inherited from the Finance group, never assigned to alice directly |
| `groups` | `["Finance"]` | Added by my Group Membership mapper |
| `aud` | `account` | The intended audience (this becomes important in Task 7) |

**Decoding is not verifying.** Anyone can read a JWT. What makes it trustworthy is the signature, which applications check with the realm's public key.

**Why it matters:** the application never looks up alice's permissions itself. It trusts the signed token. That is the core idea of SSO and federated identity.

---

## Task 7 – Validate Tokens and Fix the Audience

Asked Keycloak whether alice's brand-new token was valid using token introspection (RFC 7662):

```bash
curl -s -u expense-app:"$SECRET" -d token="$TOKEN" \
  "$KC/realms/northwind/protocol/openid-connect/token/introspect" | jq '{active, username}'
```

It returned `"active": false`:

![Introspection inactive](shot-5.png)

**Root cause:** the token's `aud` (audience) was `account`, not `expense-app`. Keycloak refuses to vouch for a token to a client that is not its intended audience. This protects against **token replay** between applications.

**Fix:** added an **Audience** mapper (`audience-expense-app`, included client audience `expense-app`, added to the access token and token introspection). After requesting a new token, introspection returned `"active": true`:

![Introspection active](shot-6.png)

---

## Task 8 – Machine Identities with Client Credentials

Requested a token for the application itself using the client credentials grant:

```bash
curl -s -d client_id=expense-app -d client_secret="$SECRET" -d grant_type=client_credentials \
  "$KC/realms/northwind/protocol/openid-connect/token" \
  | jq -r .access_token | jwt | jq '{preferred_username, azp, realm_access}'
```

![Service account token](shot-7.png)

The token belongs to `service-account-expense-app` and contains only the default roles, with **no business roles**. That is least privilege by default: the service can prove who it is but cannot approve expenses. If it needed a role, it would be granted under the client's **Service account roles** tab.

> **Security note:** the client secret is as sensitive as a password. In production it lives in a secrets manager and is rotated, never stored in source code.

---

## Task 9 – Enforce MFA for a Privileged User

Signed in as sam in a private window. After the forced password change, Keycloak required **Mobile Authenticator Setup** before activating the account.

![TOTP setup](shot-8.png)

Enrolled an authenticator labeled `sam-phone`. TOTP (RFC 6238) combines a shared secret with the current 30-second time window to produce a six-digit code.

The admin console confirmed sam now holds both a password credential and an OTP credential:

![sam credentials](shot-10.png)

**Enforcement test:**

| Login attempt | Result |
|---|---|
| Password only | ❌ `invalid_grant` – Invalid user credentials |
| Password + fresh TOTP code | ✅ Tokens issued |

**Why a fresh code?** Keycloak refuses to accept the same code twice, so a code someone saw over your shoulder is useless once it has been used.

---

## Task 10 – Detect a Password-Guessing Attack

Simulated an attacker guessing alice's password six times:

![Brute force attempts](shot-11.png)

Every attempt returned HTTP 400, **including the sixth**, after the lockout had triggered. Then I tried alice's **correct** password in the browser, and it still failed with the same generic error:

![Locked account login](shot-12.png)

Keycloak deliberately returns the same generic message so an attacker cannot tell they have triggered a lockout.

### Investigating as the SOC

The user events for alice show the burst of `LOGIN_ERROR` entries, all from the same source IP (`172.18.0.2`) through `expense-app` at the same minute:

![Login error events](shot-13.png)

| Indicator | Observation |
|---|---|
| Event type | `LOGIN_ERROR` (invalid credentials, then temporarily disabled) |
| Source IP | `172.18.0.2` |
| Client | `expense-app` |
| Time | September 28, 2026, 7:56 PM (server time) |
| Pattern | Rapid consecutive failures from one source, consistent with password guessing |

**Response:** after confirming the activity was not alice's, I unlocked her account from her user page and confirmed her real password worked again.

---

## Task 11 – Offboard a Leaver and Review Access

Alice has resigned, and offboarding must take effect immediately, including tokens she already holds.

1. Requested a fresh token for alice and confirmed it introspected as active.
2. Disabled alice's account and signed out her sessions.

![alice disabled](shot-14.png)

3. Introspected the **same** token again. It now returns `"active": false`, so every API that validates tokens rejects alice instantly:

![Introspection after disable](shot-15.png)

**Why disable instead of delete?** Deleting a user destroys the audit trail and can orphan records. Most organizations disable immediately and delete later according to their data-retention policy.

### Audit evidence

The admin events log records every change made during the lab, including the client creation, both protocol mappers (groups and audience), the user creations, and alice's final update when she was disabled:

![Admin events](shot-16.png)

### Access review note

| Privileged role | Held by (via group) | Status |
|---|---|---|
| `it-admin` | IT group, no members | No active holders |
| `soc-analyst` | sam (Security Operations) | Active, MFA enrolled |
| `finance-approver` | alice (Finance) | **Disabled**, leaver |

- **MFA coverage:** sam, the only active privileged user, has an OTP credential (`sam-phone`). alice had password-only access and is now disabled.
- **Disabled accounts:** alice, disabled September 28, 2026 at 8:00 PM (server time), as recorded in the admin events log.
- **Findings:** no roles are assigned directly to users; all access flows through group membership.

---

## Work checklist

- [x] `northwind` realm with password policy, brute-force lockout, and event logging
- [x] Four realm roles mapped to three groups, with no roles assigned directly to users
- [x] alice and sam created with temporary passwords, and sam required to enroll OTP
- [x] Confidential `expense-app` client with group and audience mappers
- [x] Decoded an access token and explained `iss`, `sub`, `azp`, `exp`, roles, and groups
- [x] Explained why introspection failed before the audience mapper
- [x] Obtained a service-account token and explained why it has no business roles
- [x] Proved sam's login requires both a password and a TOTP code
- [x] Found the brute-force events and unlocked the account
- [x] Disabled a leaver and proved their existing token stopped working

## Key Takeaways

1. **Isolate identities by realm.** Keep platform administrators separate from the workforce.
2. **Roles on groups, people in groups.** Joiner-mover-leaver changes become single, auditable edits.
3. **Tokens carry authorization.** Applications trust signed claims instead of looking up permissions themselves.
4. **Audience restriction prevents token replay** between applications.
5. **Machine identities get least privilege by default.**
6. **MFA belongs on privileged accounts first**, and TOTP codes cannot be reused.
7. **Lockouts should be silent to attackers** but visible to defenders through event logs.
8. **Offboarding must revoke live tokens**, not just block future logins.

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 6238: TOTP Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
