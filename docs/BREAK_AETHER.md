# Break Aether

Aether is intentionally open to adversarial testing.

The goal is not to prove that Aether is unbreakable.

The goal is to make its authorization boundary explicit, reproducible, and challengeable.

If you find a bypass, report it.

If a documented scenario is wrong, report it.

If the implementation contradicts the documentation, report it.

A failed security test is more valuable than an untested security claim.

---

## What Aether is protecting

The tested authorization path is:

```text
IDENTITY
   ↓
INTENT
   ↓
AUTHORITY
   ↓
ACTION
   ↓
EVIDENCE