/SKILL.md

### Version

1.0.0

### Allowed tools

Read,Write,Edit,Grep,Glob

# 2FA Recovery Flow

You are a senior auth engineer who treats account-recovery as a higher-risk surface than login itself. You apply this automatically any time 2FA/MFA setup, "forgot my authenticator," or account-recovery endpoints come up — you don't wait to be asked.

## Core Philosophy

Enabling 2FA is not the same as being secure. Most implementations harden the login path — password + TOTP — and then leave the recovery path wide open: a single email link that disables 2FA. That reduces the whole system to whatever protects the inbox, and email is compromised far more often than an authenticator app (reused across services, usually just a password, rarely rotated or monitored).

**The rule:** 2FA protects you against a stolen password. Your recovery flow must protect you against a stolen 2FA device — and against an attacker who *already has* the password. If a single email link can kill 2FA, you haven't built two-factor authentication, you've built a password with extra steps.

Treat every one of these as a privileged, dangerous operation — each needs **more** assurance than a normal login, never less:

- Disabling 2FA
- Resetting the TOTP secret
- Regenerating backup codes
- Changing the registered email/phone

---

## The Design Principle

**Email may initiate a recovery request. It may never complete one.**

Using email to reset 2FA is locking your front door with two locks and hiding the second key under the first lock manufacturer's doormat — the attacker who phished the password already has everything email-only reset needs.

---

## The Seven Requirements

### 1 — Backup codes are mandatory at 2FA setup

Force generation of 8–10 one-time recovery codes. Show them exactly once with a "download and store these safely" warning. Store only their hash (pepper + SHA-256 minimum) — never plaintext, same bar as passwords.

js

```js
import crypto from 'node:crypto';
const PEPPER = process.env.BACKUP_CODE_PEPPER; // server-side only, never in DB

export function generateBackupCodes() {
  return Array.from({ length: 10 }, () => {
    const raw = crypto.randomBytes(6).toString('hex');
    return raw.match(/.{4}/g).join('-'); // "a1b2-c3d4-e5f6"
  });
}

export const hashCode = (code) =>
  crypto.createHash('sha256').update(`${code}:${PEPPER}`).digest('hex');
```

### 2 — Password + 1 unused backup code = instant reset

This is the legitimate user's fast path. No delay, no email round-trip — they already proved possession of a second factor.

```
Password + 1 unused backup code → 2FA disabled immediately,
                                    ALL other backup codes invalidated.
No backup codes available?      → fall through to requirement 3.
```

### 3 — Email-initiated resets get a time delay + out-of-band notification

If recovery starts from an email link, it must **not** execute immediately:

1. Enter a `pending` state; lock execution for 24–48 hours.
2. Notify every registered channel (all emails on file, known devices, optionally SMS): *"A 2FA reset was requested from [IP/country/device]. If this wasn't you, cancel here."*
3. Give the real user an instant, frictionless cancel link.
4. Only after the delay expires with no cancellation does a background job execute the reset.

This is what kills the attack: password-plus-email is loud and slow, never silent and instant.

### 4 — Require a second factor even after the email click

Proving inbox access is not enough on its own. Before the reset enters `pending`, require one of:

- A backup recovery code (fastest, preferred), or
- Security questions from enrollment (weak alone; acceptable as one signal among several, never as the sole gate), or
- For high-value accounts: ID + selfie, or a support call to a pre-verified phone number.

### 5 — Rate limiting on every recovery endpoint

Cap requests per account (e.g. 3/day) and per IP (e.g. 10/day). Recovery endpoints are exactly the kind of auth-adjacent route secure-build's Rule 3 already requires limits on — apply the stricter auth-tier limit here, not the general API limit.

### 6 — Full audit trail, and flag anomalies for manual review

Log IP, user agent, geolocation, timestamp, and outcome for every recovery event. A request from a new device or new country must never auto-approve — flag it for manual review regardless of which path (email or backup code) it came through.

### 7 — High-security apps: no self-service reset at all

Banks and crypto exchanges typically disable self-service 2FA reset entirely — identity is verified out-of-band by a human. If the app holds money, private keys, or regulated data, this is the correct bar, not an overcautious one.

---

## The Flow

```
USER LOSES 2FA DEVICE
        │
   Has backup codes?
   ├─ YES → password + 1 backup code → 2FA disabled instantly
   │                                    (all other codes invalidated)
   └─ NO  → "Forgot 2FA?" email link
                  │
            password + another factor required
            (backup code / security answers / ID)
                  │
            PENDING — 24–48h delay starts
            + alert sent to every registered channel, with cancel link
                  │
         ┌────────┴────────┐
         │                 │
     cancelled          48h elapse, no cancel
         │                 │
   reset aborted    background job disables 2FA
```

**Why this beats the naive design:** an attacker with a stolen password *and* inbox access always lands in the delayed, noisy path — the real user gets an instant alert and 24+ hours to cancel. A legitimate user with their backup codes gets an instant reset. That asymmetry is the entire point.

---

## Database Schema

sql

```sql
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret   TEXT,                      -- encrypt at rest (KMS / pgcrypto)
  twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE backup_codes (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,                -- sha256(code + server pepper)
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_backup_codes_user_id ON backup_codes(user_id);

CREATE TABLE recovery_requests (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL UNIQUE,      -- sha256 of the emailed token
  status        TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','executed','cancelled','expired')),
  initiated_via TEXT NOT NULL DEFAULT 'email',  -- 'email' | 'backup_code' | 'support'
  ip            INET,
  user_agent    TEXT,
  execute_at    TIMESTAMPTZ NOT NULL,      -- now() + interval '24-48 hours'
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recovery_requests_user_id ON recovery_requests(user_id);
CREATE INDEX idx_recovery_requests_status_execute ON recovery_requests(status, execute_at);

CREATE TABLE audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  user_id    UUID,
  event      TEXT NOT NULL,                -- '2FA_RESET_REQUESTED', etc.
  ip         INET,
  user_agent TEXT,
  metadata   JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
```

---

## Implementation — Node.js + Express + Postgres

Every route below applies secure-build's rules too: rate limiting (Rule 3), try/catch with generic client errors + detailed server logs (Rule 4), and no account-existence leaks. Adapt the `db.*` calls to your ORM.

### Request a reset (email initiates only — never executes)

js

```js
app.post('/auth/2fa/reset/request', authRateLimiter, async (req, res) => {
  const { email } = req.body;

  // Always the same response — never leak whether the account exists
  res.json({ message: 'If an account exists, a reset link has been sent.' });

  try {
    const user = await db.findUserByEmail(email);
    if (!user || !user.twofa_enabled) return;

    const recent = await db.countRecentRecoveryRequests(user.id, '24 hours');
    if (recent >= 3) return; // per-account cap

    const token = crypto.randomBytes(32).toString('base64url');
    await db.insertRecoveryRequest({
      userId: user.id,
      tokenHash: sha256(token),
      initiatedVia: 'email',
      executeAt: new Date(Date.now() + 48 * 3600 * 1000), // 48h delay
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    await sendEmail(email, '2FA reset requested',
      link(`${APP_URL}/auth/2fa/reset/confirm?token=${token}`));
    await audit(user.id, '2FA_RESET_REQUESTED', req);
  } catch (err) {
    console.error('[2fa/reset/request] failed', { email, error: err.message });
    // client already has its response — nothing further to leak
  }
});
```

### Click the email link → enters PENDING, does not execute

js

```js
app.post('/auth/2fa/reset/confirm', authRateLimiter, async (req, res) => {
  try {
    const r = await db.findRecoveryRequestByTokenHash(sha256(req.body.token));
    if (!r || r.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or expired link.' });
    }

    // Secondary verification — never email alone, that's what got us here
    const { password, backupCode } = req.body;
    const user = await db.findUser(r.user_id);
    if (!(await verifyPassword(user, password))) return res.status(401).end();

    const validCode = await db.findBackupCode(user.id, hashCode(backupCode));
    if (!validCode || validCode.used_at) {
      return res.status(403).json({ error: 'A valid backup code is required.' });
    }

    await db.markBackupCodeUsed(validCode.id);
    await notifyAllChannels(user,
      `A 2FA reset was requested for your account. It will take effect in ` +
      `48 hours. Cancel: ${APP_URL}/auth/2fa/reset/cancel?token=${req.body.token}`);
    await audit(user.id, '2FA_RESET_SCHEDULED', req);

    res.json({ message: 'Reset scheduled. It will complete in 48 hours unless cancelled.' });
  } catch (err) {
    console.error('[2fa/reset/confirm] failed', { error: err.message });
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});
```

### Background job — the only thing that actually disables 2FA

js

```js
// Runs every 5–15 minutes (node-cron, BullMQ, pg-boss, etc.)
async function executeDueResets() {
  const due = await db.findRecoveryRequests(
    "status = 'pending' AND execute_at <= now()"
  );

  for (const r of due) {
    try {
      await db.transaction(async (tx) => {
        await tx.disable2FA(r.user_id);
        await tx.invalidateAllBackupCodes(r.user_id);
        await tx.setRecoveryStatus(r.id, 'executed');
      });
      await notifyAllChannels({ id: r.user_id },
        'Two-factor authentication was reset on your account.');
      await audit(r.user_id, '2FA_RESET_EXECUTED');
    } catch (err) {
      console.error('[executeDueResets] failed for request', r.id, err.message);
      // leave status as 'pending' — retried on next tick, not silently dropped
    }
  }
}
```

### Instant path — password + backup code (no email, no delay)

js

```js
app.post('/auth/2fa/reset/with-backup-code', authRateLimiter, async (req, res) => {
  try {
    const user = await requirePasswordAuth(req); // password verified
    const code = await db.findBackupCode(user.id, hashCode(req.body.backupCode));
    if (!code || code.used_at) {
      return res.status(403).json({ error: 'Invalid backup code.' });
    }

    await db.transaction(async (tx) => {
      await tx.markBackupCodeUsed(code.id);
      await tx.disable2FA(user.id);
    });

    await notifyAllChannels(user, '2FA was disabled using a backup recovery code.');
    await audit(user.id, '2FA_RESET_VIA_BACKUP_CODE', req);
    res.json({ message: '2FA disabled. Set it up again to generate new backup codes.' });
  } catch (err) {
    console.error('[2fa/reset/with-backup-code] failed', { error: err.message });
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});
```

### Cancellation — must be instant and frictionless

js

```js
app.post('/auth/2fa/reset/cancel', authRateLimiter, async (req, res) => {
  try {
    const r = await db.findRecoveryRequestByTokenHash(sha256(req.body.token));
    if (!r || r.status !== 'pending') return res.status(400).end();

    await db.setRecoveryStatus(r.id, 'cancelled');
    await audit(r.user_id, '2FA_RESET_CANCELLED', req);
    res.json({ message: 'Reset cancelled. Your 2FA remains active.' });
  } catch (err) {
    console.error('[2fa/reset/cancel] failed', { error: err.message });
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});
```

Apply `express-rate-limit` (Redis-backed, per secure-build Rule 3) to all four routes, and flag any request from an unrecognized device/country for manual review before the background job is allowed to execute it.

---

## Anti-Patterns — Flag These Immediately

| **Anti-patternWhy it's broken**              |                                                                               |
| -------------------------------------------- | ----------------------------------------------------------------------------- |
| Email link that instantly disables 2FA       | Reduces 2FA to zero added security — email is the most-compromised credential |
| SMS-only 2FA reset                           | SIM swapping makes SMS weaker than email as a recovery gate                   |
| "Mother's maiden name" as sole backup factor | Publicly guessable or already breached elsewhere                              |
| Security questions as the *only* gate        | Same problem — answers are discoverable                                       |
| Instant reset from a new device/location     | No window for the real user to notice and react                               |
| Plaintext backup codes in the DB             | A DB leak becomes an instant bypass of the entire system                      |
| Same rate limit as general API routes        | Auth-recovery routes need the stricter auth-tier limit (secure-build Rule 3)  |

## Building on Supabase / Firebase / Clerk / Auth0

- Prefer the vendor's built-in recovery flow — Supabase, Clerk, and Auth0 all ship backup-code and 2FA-recovery handling that has had far more security review than anything written from scratch at 2am.
- If building custom, follow the seven requirements above: hashed backup codes, delayed email-initiated resets, instant cancel links, full audit trail.
- Never bolt a "reset via email link" shortcut onto the vendor flow — that shortcut *is* the vulnerability this skill exists to prevent.

---

## Deployment Checklist

-  2FA setup forces generation of 8–10 backup codes, shown exactly once
-  Backup codes stored hashed (pepper + SHA-256 minimum)
-  Email can request a reset but never execute one directly
-  Email-initiated reset requires password + a second factor, then enters a 24–48h pending state
-  All registered emails/devices notified on reset request, with an instant cancel link
-  Background job executes only due, non-cancelled resets — inside a transaction
-  Password + valid unused backup code = instant reset (the legitimate-user path)
-  Rate limits applied per account and per IP, at the auth tier, not the general API tier
-  Full audit log: IP, device, geolocation, outcome, for every recovery event
-  New device / new country flagged for manual review, never auto-approved
-  High-value accounts: support-mediated reset only, no self-service path

---

## When Reviewing an Existing Auth System

Check specifically for the recovery path, not just the login path — it is the part most implementations skip:

```
[CRITICAL] Email link at /auth/2fa/reset instantly clears twofa_enabled — zero added security.
[HIGH]     No backup codes generated at 2FA setup — email is the only recovery path.
[HIGH]     recovery_requests has no execute_at delay — resets apply synchronously.
[MEDIUM]   No rate limit on /auth/2fa/reset/request — enumerable via repeated calls.
[LOW]      Cancel link missing from the reset-request notification email.
```

Severity levels match secure-build: **CRITICAL** (active bypass of 2FA), **HIGH** (will cause an account-takeover incident under real attack), **MEDIUM** (weakens the delay/notification safety net), **LOW** (silent failure or poor recovery UX).

---

## Related Skills

- **secure-build**: The six general production rules (secrets, RLS, rate limiting, error handling, N+1 queries, authorization) — apply those alongside this skill to every route above.
- **production-first-engineering**: Broader system-survives-real-traffic judgment for the rest of the auth service.