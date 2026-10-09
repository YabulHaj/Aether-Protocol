# Break Aether

## Do not just trust the authorization result. Test it.

Aether is an open-source authorization and enforcement research project for autonomous software agents.

The challenge is simple: find a reproducible case where the implementation behaves differently from its documented security boundary.

**Start with the existing 50-scenario Attack Lab. Then challenge an assumption it does not cover.**

[Report a finding](https://github.com/YabulHaj/Aether-Protocol/issues/new?template=break-aether.yml) | [Read the threat model](./THREAT_MODEL.md) | [Report a sensitive vulnerability](../SECURITY.md)

## Your first 10-minute experiment

You need Git and Go installed.

### 1. Get the repository

```bash
git clone https://github.com/YabulHaj/Aether-Protocol.git
cd Aether-Protocol
```

### 2. Run the complete Attack Lab corpus

From the repository root, run:

```powershell
go test -count=1 -v ./cmd -run '^TestAttackLabExtended$'
```

This invokes the 50-scenario corpus: the 20 core scenarios plus the extended scenarios.

The tests use a local in-process HTTP server and a counting test backend. They do not require you to target a third-party system.

### 3. Examine the security invariant

For an authorized baseline request, the expected backend request count increases by one.

For a blocked, malformed, revoked, or out-of-policy request, the expected backend request count does not increase.

The test also checks the expected HTTP result and, where applicable, the corresponding evidence reason and evidence integrity.

The key question is:

**Did an unauthorized action reach the protected target?**

A denial response alone does not establish that property.

### 4. Try a boundary the corpus may not cover

Start with one of these existing cases:

| Scenario       | Challenge area            |
| -------------- | ------------------------- |
| `AET-ATT-0043` | Escalated target resource |
| `AET-ATT-0044` | Escalated intent          |
| `AET-ATT-0045` | Capability wildcard       |
| `AET-ATT-0048` | Revoked identity          |
| `AET-ATT-0049` | Revoked nonce             |

Choose one and ask: **What nearby variation could challenge the same security invariant?**

Examples include changing one action-envelope field, trying a boundary value, testing a missing field, or examining a concurrency edge case.

Keep experiments local. Do not test third-party systems without explicit authorization. Do not weaken the expected security property just to make a test pass.

## What counts as a useful finding?

A suspected bypass deserves investigation when, for example:

* an unauthorized request reaches the backend;
* an out-of-scope action is allowed;
* revoked authority continues to work;
* replay or freshness controls fail under a defined condition;
* evidence integrity or decision-to-evidence correspondence fails.

A test failure is not automatically a confirmed bypass. It may be an implementation defect, a test defect, or an infrastructure problem. Report the observed facts and let reproduction establish the classification.

## Report what happened

[Open a Break Aether report](https://github.com/YabulHaj/Aether-Protocol/issues/new?template=break-aether.yml)

Include:

* the Aether commit or release you tested;
* the scenario ID or security property;
* exact reproduction steps and command;
* expected and observed HTTP results;
* expected and observed backend request counts, when applicable;
* relevant non-sensitive logs;
* whether you reproduced the result more than once.

Do not include API keys, bearer tokens, private keys, personal data, or confidential material in a public issue. Follow [SECURITY.md](../SECURITY.md) for sensitive vulnerability reports.

If you cannot reproduce the result reliably, report that too. An inconclusive result is more useful than an unsupported claim.

## What happens next?

The intended workflow is:

**Finding -> Independent reproduction -> Classification -> Regression test, when appropriate -> Fix or documented limitation -> Updated evidence**

Confirmed bypasses should produce regression tests. Fixes should preserve the original finding and its history rather than erase inconvenient results.

A passing Attack Lab run establishes only the behavior observed in that defined corpus and environment. It does not prove universal security or establish independent validation by itself.

## The principle

> No action without authorization.
> No authorization without context.
> No security claim without evidence.
