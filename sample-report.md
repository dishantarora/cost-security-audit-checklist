> Illustrative output. The account, resource IDs, and findings below are fictional.

# AWS cost and security audit

- **Account:** `123456789012`
- **Region checked:** `us-east-1` (IAM is account-wide)
- **Generated:** 2026-10-02 12:00 UTC

## Summary

- **Cost review candidates:** 5
- **Unattached EBS:** 1 volume(s), 100 GiB total
- **Stopped compute:** 2 EC2 instance(s), 1 RDS instance(s)
- **Unassociated Elastic IPs:** 1
- **Untagged resources:** 3
- **IAM wildcard findings:** 1 critical, 2 for review across 22 policy document attachment(s)
- **Checks with errors:** 0

## Cost review candidates

These are indicators to review, not automatic deletion recommendations or dollar estimates.

### Stopped EC2 instances
- `i-0a12bc34de56f7890` (`t3.large`)
- `i-0b98cd76ef54a3210` (`m6i.large`)

### Unattached EBS volumes
- `vol-0123abcd4567ef890` (100 GiB)

### Unassociated Elastic IPs
- `eipalloc-0123abcd4567ef890` (`198.51.100.24`)

### Stopped RDS instances
- `audit-staging-db` (`postgres`)

## IAM policy review

- **CRITICAL** `role/LegacyAdminRole` — policy `LegacyAdminAccess`, statement `AdminAccess`: Allow grants Action * on Resource * (matched: `*`)
- **REVIEW** `user/ci-deploy` — policy `DeployPolicy`, statement `DeployAll`: Allow grants a service-wide action wildcard on Resource *; verify the actions and conditions (matched: `s3:*`)
- **REVIEW** `role/OrgAuditRole` — policy `OrgBoundaryException`, statement `ExcludingActions`: Allow uses NotAction or NotResource; inspect the effective permissions manually (matched: `NotAction/NotResource`)

## Untagged resources

- EC2 instance: `i-0a12bc34de56f7890`
- EBS volume: `vol-0123abcd4567ef890`
- Elastic IP: `eipalloc-0123abcd4567ef890`

## Scan limitations

- The regional resource checks cover EC2 instances, EBS volumes, Elastic IPs, and RDS DB instances. Run once per region you want to review.
- Untagged means the resource has no tags. This does not validate required tag keys or tag values.
- Stopped instances and unattached resources can be intentional. Review ownership and dependencies before changing anything.
- IAM checks flag selected wildcard grants and `NotAction`/`NotResource` statements. They do not calculate effective permissions, evaluate conditions, or replace IAM Access Analyzer and a human review.
- No dollar estimate or utilization analysis is included; use Cost Explorer and monitoring metrics for those.
