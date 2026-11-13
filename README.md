# chef-compliance-autogen

**Compliance-as-code generator and test platform.** One YAML benchmark file produces both
a **Chef InSpec profile** (scan) and a **Chef Infra remediation cookbook** (fix). A CI
pipeline then shows that the generated content works on a real system:

```
benchmarks/*.yml ──► generator (Python) ──► build/profiles/<name>/   InSpec controls
                                        └─► build/cookbooks/<name>_remediation/   Chef recipe

CI test platform (GitHub Actions + Docker):
  insecure Ubuntu container ──scan──► FAIL (exit 100)
                            ──Chef──► remediated
                            ──scan──► PASS (exit 0)
                            ──Chef──► "0/N resources updated"  (idempotent)
```

## Why this exists

A real benchmark (CIS, DISA STIG) has hundreds of rules. Writing an InSpec control **and** a
matching Chef fix by hand for every rule is slow, and the two drift apart. Here a rule is
written once as data, and the scan and the fix are generated from it, so they always match.

## Layout

| Path | What it is |
|---|---|
| `benchmarks/linux_baseline.yml` | 7 CIS-inspired Linux rules (SSH, file permissions, packages, password policy) |
| `benchmarks/aws_dr_storage.yml` | 3 scan-only S3 rules using the **inspec-aws** resource pack, with an InSpec `input` for the bucket name |
| `generator/rules.py` | One class per rule type: validate params → render InSpec → render Chef |
| `generator/generate.py` | Loads and validates YAML, writes profiles and cookbooks |
| `build/` | Generated output, committed so reviewers can read it (tests fail if it's stale) |
| `test-platform/` | Deliberately non-compliant Dockerfile + the scan → fix → rescan script |
| `.github/workflows/compliance.yml` | CI pipeline |
| `tests/` | pytest unit tests for the generator |

## Rule types

| Type | InSpec resource | Chef remediation |
|---|---|---|
| `sshd_option` | `sshd_config` | `ruby_block` editing `/etc/ssh/sshd_config` |
| `login_defs` | `login_defs` | `ruby_block` editing `/etc/login.defs` |
| `file_permissions` | `file` + `be_more_permissive_than` | `file` (owner/group/mode) |
| `package_absent` | `package` | `package … action :remove` |
| `aws_s3_bucket` | `aws_s3_bucket` (inspec-aws) | scan-only |

Adding a rule type means writing one class with `validate`, `inspec` and `chef` methods.

## Run it

```bash
pip install -r requirements.txt
python -m generator          # regenerate build/ from benchmarks/
pytest -q                    # unit tests
# Needs Docker + cinc-auditor (or SCANNER=inspec):
bash test-platform/run_compliance_loop.sh
# Cloud profile (needs AWS credentials):
inspec exec build/profiles/aws-dr-storage -t aws:// --input primary_bucket=my-bucket
```

CI uses **Cinc** (the community builds of Chef InSpec and Chef Infra Client), so no
license key is needed in the pipeline. The Ruby DSL is the same.

## Design decisions

- **Idempotent remediation.** Every Chef resource has a guard, so a compliant node is left
  alone. CI enforces this: the second Chef run must report `0/N resources updated`.
- **Never loosen a stricter setting.** For limits (`compare: max`), the fix runs only when the
  current value is out of policy. `PASS_MAX_DAYS 90` stays 90; it is never "fixed" to 365.
  Permission guards work the same way.
- **Strict validation, because the output is code.** Params go into generated Ruby, so
  each one is checked against a regex and every string is escaped. A test shows that a Ruby
  injection attempt in a config key is rejected.
- **The YAML `no` → `false` trap is caught.** Unquoted `no` would be read as a boolean, and the
  generator stops with a clear message.
- **Generated code is committed and checked for drift.** The test suite regenerates
  everything and compares it with `build/`, so hand edits or forgotten regeneration fail CI.
- **Scan-only vs remediable.** Cloud rules (S3) only scan. Fixing cloud resources belongs in
  Terraform or SDK automation, not a node cookbook.

## Known limitations / next steps

- sshd is not restarted after a config change (there's no init system in the test container).
  On a real node the `ruby_block` would `notifies :restart, 'service[ssh]'`.
- `sshd_config` `Match` blocks and `Include` files are not handled.
- Next: Windows rules (registry, services, scanned over WinRM); **Test Kitchen + kitchen-dokken**
  as the test driver; more platforms in a CI matrix; and parsing CIS XCCDF benchmarks, or
  drafting rule YAML with an LLM for a human to review, so the input itself is generated too.
