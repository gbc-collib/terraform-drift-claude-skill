# Triage and HCL editing patterns

## Why triage exists

Codifying drift changes only the repo, so it is safe for the infrastructure. The risk is
different: writing a bad change into the code *launders* it. A world-open security group, a
disabled MFA rule, or a break-glass admin grant stops showing up in `terraform plan`, and the
next reviewer sees a clean diff. That is why security-relevant drift pauses for a human, and
benign drift does not.

## Decision table

| Finding | Default action | Needs the user first? |
|---|---|---|
| Benign attribute changed in the cloud (tags, descriptions, sizes, timeouts, capacity) | Edit code to match reality | No. Summarize at the end |
| `[REVIEW]` item (IAM, network exposure, encryption, logging, MFA/sign-on policy, admin roles, public access) | Do **not** edit yet. Show what changed, who changed it (attribution), and offer: codify / leave it so a later `apply` reverts it / escalate | **Yes** |
| Attribute that is routinely changed by something else (autoscaling `desired_count`, CI-updated `task_definition`/image tag, policy-injected tags, `last_modified`-style fields) | Propose `lifecycle { ignore_changes = [...] }`, scoped to the one attribute | **Yes** (it is a policy decision) |
| Sensitive value changed (password, key, secret) | Never write the value. Report that it changed. Suggest a variable/data source or `ignore_changes` | **Yes** |
| `code_ahead` (code differs, cloud did not drift) | Leave alone. This is an unapplied change, not drift | Only to confirm |
| `gone_from_cloud` | Leave the code; ask whether to delete the block (and add `removed {}`) or recreate | **Yes** |
| `in_code_not_in_cloud`, `in_state_not_in_code` | Not drift. Mention, do not touch | No |
| Drift would force a **replacement** (`replace: true`) | Editing the code to match reality *prevents* the replacement. Do it, but call it out | Mention |
| Resource exists in cloud, not in code or state | Offer to import (see below) | **Yes** (scope and which ones) |

When unsure whether something is security-relevant, treat it as `[REVIEW]`.

## Attribution (optional but valuable for `[REVIEW]` items)

Look up who changed it and when using the audit log commands in `providers.md`. One line per
item: `principal, time, action`. A change by a known engineer during an incident reads very
differently from one by an unfamiliar principal or a long-lived access key. Never decide
"malicious vs fine" for the user; present the facts and flag unfamiliar principals as worth a
security look.

## Editing HCL

1. **Edit where the value is defined.** If the attribute is `var.x`, `local.y`, a `.tfvars`
   entry, or a module input, change that source, not a hardcoded literal at the use site.
   Check every other consumer of that variable first; if it feeds several resources and only one
   drifted, set the override at the narrowest level instead.
2. **Registry/remote modules**: change the module call's inputs. Never edit vendored module
   source to chase drift.
3. **`for_each` / `count`**: adjust the map/list entry for the drifted key. Do not convert to
   hardcoded blocks.
4. **Nested and dynamic blocks**: the report path `ingress[0].cidr_blocks[0]` indexes into the
   *state* ordering, which may not match source order. Find the block by its content, not index.
5. **Preserve** comments, ordering, and formatting. Make minimal diffs. Run `terraform fmt` on
   touched files only.
6. **Prefer references over literals** when the value is another managed resource's attribute
   (`aws_vpc.main.id`, not `"vpc-0abc..."`) and the repo already does so elsewhere.
7. **Secrets**: never put them in `.tf`/`.tfvars`. Declare `variable "x" { sensitive = true }`
   with no default and tell the user how it should be supplied.
8. **Provider noise is not drift.** Signals: `null` vs `""`, `[]` vs absent, reordered sets,
   case-only changes in Azure ids, defaults added by a newer provider version. Check
   `.terraform.lock.hcl` and `required_providers`; if a provider upgrade explains it, say so and
   usually leave it.

## Imports for unmanaged resources

Use config-driven import so nothing writes to state:

```hcl
import {
  to = aws_s3_bucket.logs
  id = "acme-logs-prod"
}
```

then `guard terraform plan -lock=false -generate-config-out=generated_imports.tf`. Terraform
refuses to overwrite an existing file, so use a fresh name. Treat the generated file as a first
draft and clean it:

- delete computed-only attributes the provider rejects (`arn`, `id`, `owner_id`, ...)
- replace hardcoded ids with references to managed resources
- move the block into the file/module where similar resources live, following repo naming
- strip default-valued noise that clutters the file
- never keep secret values that appear in the generated output

Leave the `import {}` blocks in place for the user to apply; applying them is the user's
step, because it writes state. Do not run `terraform import`.

## Removing a resource from management (after the user agrees)

```hcl
removed {
  from = aws_s3_bucket.old
  lifecycle { destroy = false }
}
```

## Verification loop

```
guard terraform validate
guard terraform plan -lock=false -detailed-exitcode -out=verify.tfplan     # exit 0 = clean, 2 = changes
guard --out verify.json terraform show -json verify.tfplan
python scripts/drift_report.py verify.json
```

Repeat edit -> plan until `drift_caused` is empty. Stop after 5 rounds, or sooner if the same
attribute flips back and forth, and report it; oscillation means something else is managing that
attribute (see the `ignore_changes` row). The only items allowed to remain are the ones the
user chose to defer, and you list them explicitly.
