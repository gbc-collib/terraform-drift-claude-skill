---
name: terraform-drift-reconcile
description: Reconcile Terraform/OpenTofu code with what actually exists in the cloud, using read-only calls only. The cloud is treated as the source of truth, and the .tf files are edited until `terraform plan` is clean. Use this whenever the user mentions infrastructure drift, "ClickOps", console changes, manual changes outside Terraform, a plan showing changes nobody made, codifying or importing existing resources, "sync/align/update terraform to match prod", or reverse-applying real state into code, across AWS, Azure, GCP, Okta, or other providers. Trigger even if they never say "drift", and even if they only say "terraform plan is noisy and I don't know why".
---

# Terraform drift reconciliation (code follows reality)

Normal drift remediation pushes reality back to match the code. This skill does the reverse:
reality is the source of truth, and the **repo** is what changes. Cloud and IdP resources are
never modified.

Most of this is mechanical, and the scripts do the mechanical parts. Three judgment points
remain, and they are where this goes wrong if skipped: security-relevant drift, code that is
*ahead* of reality (an unapplied change, not drift), and resources deleted out-of-band. Those
pause for the user; everything else flows through.

## Hard rules

1. **Read-only against infrastructure and state.** Route every `terraform`, `tofu`, `aws`,
   `az`, `gcloud`, and Okta call through `scripts/ro_guard.py`. It allowlists read verbs,
   blocks secret-returning reads, masks secrets in JSON output, and refuses everything else
   (exit 126). Do not work around a denial with a raw call; if the guard blocks something you
   need, say so and ask. Never run `apply`, `refresh`, `import`, `state rm/mv/push`, `taint`, or
   `force-unlock`: they write to shared state or infra.
2. **The guard is not the security boundary, credentials are.** At the start, confirm the
   identity in use (commands in `references/providers.md`) and ask the user to confirm it is a
   read-only role. If it looks like admin, say so before proceeding.
3. **Only edit files in the working tree** (`.tf`, `.tfvars`, `.tf.json`). Don't commit or push
   unless asked. Suggest a branch.
4. **No secret values in files, commands, or messages.** If a secret drifted, report that it
   changed, never what it changed to. Cloud payloads (env vars, app settings) can contain
   secrets the masking missed, so copy only the fields you need.
5. **Never print raw `terraform show -json`**; it contains unmasked values. The guard forces
   `--out`, and you read the result through `drift_report.py`.

In the commands below, `guard` means `python <skill-dir>/scripts/ro_guard.py`. Guard options (`--out FILE`, `--check`) go
before the command, e.g. `guard --out drift.json terraform show -json drift.tfplan`. `guard --check <cmd>` tests whether a
command would be allowed without running it.

## Workflow

### 0. Scope

Establish, asking only for what you cannot infer from the repo: which directory/root module,
which workspace or environment, Terraform vs OpenTofu, and whether discovery of *unmanaged*
resources is wanted (default: no, drift on managed resources only). Check `git status` and
warn if the tree is dirty, since you are about to edit files. Verify the cloud identity (rule 2).

### 1. Detect

```bash
guard terraform init
guard terraform plan -lock=false -out=drift.tfplan
guard --out drift.json terraform show -json drift.tfplan
python <skill-dir>/scripts/drift_report.py drift.json
```

`-lock=false` is required: taking the state lock is itself a write to the backend. Use a
normal plan, not `-refresh-only`: its JSON carries both what the cloud changed
(`resource_drift`) and what the code would change (`resource_changes`), and the report
intersects them. If init or plan cannot reach the backend or providers, stop and tell the user
which permission or credential is missing; don't paper over it.

The report sorts every finding:

| Section | Meaning | Action |
|---|---|---|
| DRIFT-CAUSED | Reality moved, code did not | Codify (step 3), after triage (step 2) |
| `[REVIEW]` tag | Security-relevant heuristic fired | Pause (step 2) |
| CODE AHEAD | Code differs, cloud did *not* change | Leave alone. It is an unapplied edit, not drift |
| GONE FROM CLOUD | Deleted outside Terraform | Ask |
| IN CODE / IN STATE only | Never applied / block removed | Not drift. Mention |
| ALREADY CONSISTENT | Cloud changed but code already matches | Nothing to do |

### 2. Triage (the human checkpoints)

Read `references/triage.md` for the decision table. In short:

- **`[REVIEW]` items, sensitive values, `ignore_changes` proposals, gone-from-cloud, and any
  code-ahead conflicts**: show the user a compact list and wait. For `[REVIEW]` items add
  attribution (who/when, from the audit log commands in `references/providers.md`) so the user
  can judge. Codifying a bad change hides it from the next reviewer.
- **Everything else** (tags, sizes, descriptions, timeouts): proceed without asking and list it
  in the final summary.

Present choices per item as: *codify*, *leave it (a future apply will revert it)*, or
*escalate*. Don't batch-approve a list the user has not seen.

### 3. Edit the code

Follow the HCL patterns in `references/triage.md`: edit the value where it is defined (variable,
tfvars, module input), not the use site; keep diffs minimal; preserve comments; prefer
references to literals; never inline secrets. Use `reality` from the report as the new value.
Find nested blocks by content rather than the state index in the path. Run `terraform fmt` only
on files you touched.

### 4. Optional: unmanaged resources

Only if the user asked. Scope it to resource types already used in the repo (or ones they
name), not "the whole account". List what exists using the discovery commands in
`references/providers.md`, subtract what is in `guard terraform state list`, drop
provider-managed noise (default VPCs, service-linked roles, built-in Okta groups), and show the
user the remainder before generating anything. Then use config-driven `import {}` blocks with
`plan -generate-config-out` (never the `terraform import` CLI). Clean the generated config as
described in `references/triage.md`.

### 5. Verify

```bash
guard terraform validate
guard terraform plan -lock=false -detailed-exitcode -out=verify.tfplan   # 0 clean, 2 changes
guard --out verify.json terraform show -json verify.tfplan
python <skill-dir>/scripts/drift_report.py verify.json
```

Loop edit -> plan until DRIFT-CAUSED is empty. Cap at 5 rounds; if one attribute keeps flipping,
something else is managing it. Stop, report it, and propose `ignore_changes`. A plan can still
show changes after this: items the user deferred, CODE AHEAD, and non-drift categories. Name
each one explicitly rather than claiming "clean".

### 6. Report

Finish with a summary the user can act on:

```
Reconciled N resources in <path> (workspace <w>). plan -detailed-exitcode: <0|2>.

Codified (M):      address: attr old -> new   (one line each)
Needs your call:   [REVIEW] items with who/when, ignore_changes proposals, gone-from-cloud
Left alone:        code-ahead (unapplied) changes, in-code-only, in-state-only
Unmanaged found:   count + list (if step 4 ran)
Files changed:     list. Nothing committed.
Next step for you: review the diff; the cloud was not touched.
```

Remove scratch files (`*.tfplan`, `drift.json`, `verify.json`) when finished. They contain
unmasked values, so don't leave them lying around the repo or commit them.

## When things go sideways

- **Guard denies a command**: read the reason. If the intent was read-only, there is usually an
  equivalent allowed call (reasons name alternatives). If not, ask the user.
- **Provider not supported by the guard** (Datadog, GitHub, Kubernetes, ...): don't improvise
  raw API calls. `terraform plan` already performs the provider's own reads, so start there. If
  discovery is truly needed, propose the GET-only endpoints and get agreement before extending
  the guard (see end of `references/providers.md`).
- **Huge plan (hundreds of drifted resources)**: it's usually one cause (a provider upgrade, a
  policy that re-tags everything). Group by attribute path first; fix the cause once rather than
  editing hundreds of blocks.
- **Remote execution backends (HCP Terraform / Terraform Enterprise)**: plans run remotely and
  may not honor `-out` the same way. Use whatever speculative-plan flow the workspace supports
  and say what you used.
