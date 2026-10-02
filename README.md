# AWS Cost & Security Audit

A small, read-only Python script for surfacing common AWS cost review candidates, untagged resources, and selected broad IAM grants. It prints a Markdown report and does not modify AWS resources.

## Run it

Requires Python 3.10+ and AWS credentials configured through an AWS profile, environment variables, or an attached role.

```sh
python -m pip install -r requirements.txt
python aws_cost_security_audit.py --profile my-audit-profile --region us-east-1 --output audit-report.md
```

Omit `--profile` to use the normal AWS credential chain. The region can also come from `AWS_REGION`, `AWS_DEFAULT_REGION`, or the profile's default region. Run the script once in each region you want to inspect; IAM policy checks are account-wide. Send `--output -` or omit it to print the report to the terminal.

## Read permissions

The selected identity needs read access for these API operations:

- STS: `GetCallerIdentity`
- EC2: `DescribeInstances`, `DescribeVolumes`, `DescribeAddresses`
- RDS: `DescribeDBInstances`
- IAM: `ListRoles`, `ListUsers`, `ListGroups`, `ListAttachedRolePolicies`, `ListAttachedUserPolicies`, `ListAttachedGroupPolicies`, `ListRolePolicies`, `ListUserPolicies`, `ListGroupPolicies`, `GetRolePolicy`, `GetUserPolicy`, `GetGroupPolicy`, `GetPolicy`, `GetPolicyVersion`

If a permission is missing, the report records the failed check and marks the scan as potentially incomplete.

## What it checks

- Stopped EC2 and RDS instances, unattached EBS volumes, and unassociated Elastic IPs as **review candidates**. They may be intentional; the script never deletes or changes resources.
- Resources with no tags among the EC2 instances, EBS volumes, Elastic IPs, and RDS DB instances it can see. It does not enforce a particular tag schema.
- IAM `Allow` statements with `Action: "*"` (including resource-scoped grants) or a service-wide `service:*` action on `Resource: "*"`, plus `NotAction`/`NotResource` statements for manual review. This is a heuristic, not an effective-permissions analyzer.

It does not calculate dollar savings or utilization, and does not scan every AWS service. Use Cost Explorer, CloudWatch metrics, and IAM Access Analyzer for deeper analysis.

## Example report

See [sample-report.md](sample-report.md). Its account and findings are fictional.
