# 2FA Recovery Flow

**Secure account recovery for lost 2FA — designed so email can start recovery, but never silently bypass 2FA.**

## Why This Skill Exists

Most authentication systems secure login:

```text
Password + TOTP
```

Then they weaken the entire system with a recovery shortcut:

```text
Forgot 2FA
     ↓
Email link
     ↓
2FA disabled immediately
```

That defeats the purpose of 2FA.

This skill treats **account recovery as a higher-risk security surface than login itself**.

---

## Core Rule

> **Email may initiate a recovery request. It may never complete one.**

A stolen password plus access to the inbox should not be enough to instantly remove 2FA.

---

## The Recovery Model

```text
                    USER LOSES 2FA
                         │
                 Has backup codes?
                    ┌────┴────┐
                   YES        NO
                    │          │
          Password + code      │
                    │          ▼
                    │      Email starts
                    │       recovery
                    │          │
                    │    Password + another
                    │      factor required
                    │          │
                    │          ▼
                    │     ┌────────────┐
                    │     │  PENDING   │
                    │     │  24–48 hrs │
                    │     └─────┬──────┘
                    │           │
                    │      Alert all channels
                    │      + instant cancel
                    │           │
                    │      ┌────┴────┐
                    │      │         │
                    │   Cancel    Time expires
                    │      │         │
                    │   Abort      Execute
                    │
                    └──────────────►
                       Instant reset
```

### The important asymmetry

```text
Legitimate user
Password + backup code
        ↓
   Instant reset


Attacker
Password + email access
        ↓
   Additional verification
        ↓
    24–48h delay
        ↓
   Alerts + cancel window
```

The legitimate path is fast.

The risky path is slow, visible, and reversible.

---

## The Seven Requirements

| # | Requirement | Security purpose |
|---|---|---|
| 1 | Generate 8–10 backup codes at 2FA setup | Give users a secure recovery factor |
| 2 | Password + unused backup code → instant reset | Provide a trusted fast path |
| 3 | Email recovery → 24–48h pending state | Prevent instant email-based bypass |
| 4 | Require another factor after email click | Email access alone is not enough |
| 5 | Rate-limit every recovery endpoint | Reduce abuse and brute force |
| 6 | Full audit + anomaly review | Detect suspicious recovery attempts |
| 7 | High-value accounts may require human verification | Raise the security bar for sensitive systems |

---

## Backup Codes

Generate one-time recovery codes during 2FA setup.

```text
8–10 random codes
       │
       ▼
Show exactly once
       │
       ▼
User stores them safely
       │
       ▼
Database stores hashes only
```

Minimum storage bar:

```text
backup code
    ↓
server-side pepper
    ↓
SHA-256
    ↓
stored hash
```

Never store backup codes in plaintext.

---

## Recovery State Machine

```text
                ┌──────────────┐
                │    PENDING   │
                └──────┬───────┘
                       │
             ┌─────────┴─────────┐
             │                   │
        user cancels        execute_at reached
             │                   │
             ▼                   ▼
      ┌────────────┐       ┌────────────┐
      │ CANCELLED  │       │  EXECUTED  │
      └────────────┘       └────────────┘
```

The application should not directly disable 2FA when an email link is clicked.

The background job is responsible for executing due, non-cancelled recovery requests.

---

## Recommended Data Model

```text
users
 ├── twofa_enabled
 └── totp_secret

backup_codes
 ├── user_id
 ├── code_hash
 └── used_at

recovery_requests
 ├── user_id
 ├── token_hash
 ├── status
 ├── initiated_via
 ├── execute_at
 ├── ip
 └── user_agent

audit_logs
 ├── user_id
 ├── event
 ├── ip
 ├── user_agent
 ├── metadata
 └── created_at
```

---

## Endpoint Model

```text
POST /auth/2fa/reset/request
        │
        └── starts recovery only

POST /auth/2fa/reset/confirm
        │
        └── verifies identity
             → creates pending reset

POST /auth/2fa/reset/cancel
        │
        └── cancels pending reset

POST /auth/2fa/reset/with-backup-code
        │
        └── trusted fast path
             → immediate reset
```

All recovery endpoints should use the stricter authentication/recovery rate limits and generic client-facing errors.

---

## Anti-Patterns

```text
❌ Email link → instantly disable 2FA
❌ SMS-only recovery
❌ Security questions as the only factor
❌ Instant reset from a new device/location
❌ Plaintext backup codes in the database
❌ General API rate limits on recovery endpoints
```

### The biggest mistake

```text
Password stolen
      +
Email stolen
      ↓
Instant 2FA reset
      ↓
Attacker owns account
```

That is not a secure 2FA recovery design.

---

## High-Value Accounts

For systems holding:

```text
Money
Private keys
Regulated data
Highly sensitive information
```

consider removing self-service 2FA reset entirely.

```text
Recovery request
      ↓
Identity verification
      ↓
Human / support review
      ↓
Reset
```

---

## Vendor-Based Systems

When using Supabase, Firebase, Clerk, Auth0, or another identity provider:

> Prefer the vendor's built-in recovery mechanisms where they already provide secure 2FA recovery.

Do not add a custom email shortcut that bypasses the provider's security model.

---

## Review Checklist

Use this skill when reviewing an existing auth system.

```text
[CRITICAL] Email link instantly disables 2FA
[HIGH]     No backup codes
[HIGH]     No recovery delay
[HIGH]     Email is the only recovery factor
[MEDIUM]   No recovery rate limit
[MEDIUM]   No anomaly detection / review
[LOW]      No cancellation path
```

---

## What This Skill Enforces

This skill pushes implementations toward:

```text
Secure recovery
      +
Strong verification
      +
Delayed risky actions
      +
User-visible alerts
      +
Instant cancellation
      +
Rate limiting
      +
Auditability
      +
Manual review when risk is high
```

## Related Skills

- **secure-build** — general security and reliability rules
- **production-first-engineering** — production-scale engineering judgment

---

## Final Principle

> **2FA is only as strong as its recovery flow.**

Protect the recovery path as aggressively as the login path — and treat risky recovery actions as privileged operations.
