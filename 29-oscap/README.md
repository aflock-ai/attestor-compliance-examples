# 29 — `oscap` ✅ validated against real infrastructure

Real OpenSCAP SSG (SCAP Security Guide) scan against the validation VM. Uses the `xccdf_org.ssgproject.content_profile_standard` profile from `ssg-amzn2023-ds.xml`. Output: XCCDF results XML, hash-attested by cilock.

## Predicate excerpt

```json
{
  "reportFile": "oscap-results.xml",
  "reportDigestSet": {
    "sha256": "583ad7852ced319100d392bff545d5c45dbe9cc98383eb5a6ab574d97a450116"
  },
  "scanSummary": {
    "profile": "xccdf_org.ssgproject.content_profile_standard",
    "benchmarkId": "xccdf_org.ssgproject.content_benchmark_AL-2023",
    "targetSystem": "ip-REDACTED.ec2.internal",
    "passCount": 11,
    "failCount": 3,
    "notApplicableCount": 64,
    "errorCount": 0,
    "failedRules": [
      {
        "idref": "xccdf_org.ssgproject.content_rule_rpm_verify_permissions",
        "severity": "high",
        "result": "fail"
      },
      {
        "idref": "xccdf_org.ssgproject.content_rule_file_permissions_library_dirs",
        "severity": "medium",
        "result": "fail"
      },
      {
        "idref": "xccdf_org.ssgproject.content_rule_grub2_nousb_argument",
        "severity": "unknown",
        "result": "fail"
      }
    ]
  }
}
```

## What we found

11 pass, 3 fail, 64 N/A on a fresh AL2023 EC2 host. Failed rules: `rpm_verify_permissions` (high), `file_permissions_library_dirs` (medium), `grub2_nousb_argument`. These are real findings — the host genuinely has these gaps.

## Reproduce

```bash
oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_standard \
    --results oscap-results.xml \
    /usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml
```
