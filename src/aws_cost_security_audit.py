#!/usr/bin/env python3
"""Read-only AWS account audit for common cost and security review items."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote


def items(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterable[dict[str, Any]]:
    """Yield every item from a paginated boto3 operation."""
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(result_key, [])


def record_error(errors: list[dict[str, str]], check: str, exc: Exception) -> None:
    response = getattr(exc, "response", {})
    code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
    errors.append({"check": check, "error": code or type(exc).__name__})


def is_untagged(tags: Any) -> bool:
    return not tags


def scan_regional_resources(session: Any, region: str, report: dict[str, Any]) -> None:
    ec2 = session.client("ec2", region_name=region)

    try:
        for reservation in items(ec2, "describe_instances", "Reservations"):
            for instance in reservation.get("Instances", []):
                state = instance.get("State", {}).get("Name", "unknown")
                if state == "terminated":
                    continue
                instance_id = instance.get("InstanceId", "unknown")
                tags = instance.get("Tags", [])
                if is_untagged(tags):
                    report["untagged"].append({"type": "EC2 instance", "id": instance_id})
                if state == "stopped":
                    report["cost_candidates"]["stopped_ec2"].append(
                        {"id": instance_id, "type": instance.get("InstanceType", "unknown")}
                    )
    except Exception as exc:  # keep other checks useful when one permission is missing
        record_error(report["errors"], "EC2 instances", exc)

    try:
        for volume in items(ec2, "describe_volumes", "Volumes"):
            volume_id = volume.get("VolumeId", "unknown")
            if is_untagged(volume.get("Tags", [])):
                report["untagged"].append({"type": "EBS volume", "id": volume_id})
            if volume.get("State") == "available":
                report["cost_candidates"]["unattached_ebs"].append(
                    {"id": volume_id, "size_gib": int(volume.get("Size", 0))}
                )
    except Exception as exc:
        record_error(report["errors"], "EBS volumes", exc)

    try:
        for address in items(ec2, "describe_addresses", "Addresses"):
            address_id = address.get("AllocationId") or address.get("PublicIp", "unknown")
            if is_untagged(address.get("Tags", [])):
                report["untagged"].append({"type": "Elastic IP", "id": address_id})
            if not address.get("AssociationId"):
                report["cost_candidates"]["unassociated_eips"].append(
                    {"id": address_id, "public_ip": address.get("PublicIp", "unknown")}
                )
    except Exception as exc:
        record_error(report["errors"], "Elastic IP addresses", exc)

    try:
        rds = session.client("rds", region_name=region)
        for db in items(rds, "describe_db_instances", "DBInstances"):
            db_id = db.get("DBInstanceIdentifier", "unknown")
            if is_untagged(db.get("TagList", [])):
                report["untagged"].append({"type": "RDS DB instance", "id": db_id})
            if db.get("DBInstanceStatus") == "stopped":
                report["cost_candidates"]["stopped_rds"].append(
                    {"id": db_id, "engine": db.get("Engine", "unknown")}
                )
    except Exception as exc:
        record_error(report["errors"], "RDS DB instances", exc)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def decode_policy_document(document: Any) -> dict[str, Any] | None:
    if isinstance(document, dict):
        return document
    if not isinstance(document, str):
        return None
    for candidate in (document, unquote(document)):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return None


def wildcard_findings(document: dict[str, Any], policy_name: str, principal: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    statements = as_list(document.get("Statement"))
    for statement in statements:
        if not isinstance(statement, dict) or str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = as_list(statement.get("Action"))
        resources = as_list(statement.get("Resource"))
        wildcard_actions = [
            action for action in actions
            if isinstance(action, str) and (action == "*" or action.endswith(":*"))
        ]
        wildcard_resource = any(resource == "*" for resource in resources)
        if wildcard_actions and (wildcard_resource or "*" in wildcard_actions):
            global_admin = "*" in wildcard_actions and wildcard_resource
            if global_admin:
                reason = "Allow grants Action * on Resource *"
            elif "*" in wildcard_actions:
                reason = "Allow grants Action * on a scoped Resource; verify the full action set"
            else:
                reason = "Allow grants a service-wide action wildcard on Resource *; verify the actions and conditions"
            findings.append(
                {
                    "severity": "critical" if global_admin else "review",
                    "policy": policy_name,
                    "principal": principal,
                    "statement": statement.get("Sid", "(unnamed statement)"),
                    "actions": ", ".join(str(action) for action in wildcard_actions),
                    "reason": reason,
                }
            )
        elif "NotAction" in statement or "NotResource" in statement:
            findings.append(
                {
                    "severity": "review",
                    "policy": policy_name,
                    "principal": principal,
                    "statement": statement.get("Sid", "(unnamed statement)"),
                    "actions": "NotAction/NotResource",
                    "reason": "Allow uses NotAction or NotResource; inspect the effective permissions manually",
                }
            )
    return findings


def scan_iam(session: Any, report: dict[str, Any]) -> None:
    iam = session.client("iam")
    entities: list[tuple[str, str]] = []
    for operation, result_key, kind, name_key in (
        ("list_roles", "Roles", "role", "RoleName"),
        ("list_users", "Users", "user", "UserName"),
        ("list_groups", "Groups", "group", "GroupName"),
    ):
        try:
            for entity in items(iam, operation, result_key):
                entities.append((kind, entity[name_key]))
        except Exception as exc:
            record_error(report["errors"], f"IAM {kind} listing", exc)

    managed: dict[str, set[str]] = {}
    inline: list[tuple[str, str, str, Any]] = []
    for kind, name in entities:
        if kind == "role":
            attached_op, attached_key, inline_op, inline_key = (
                "list_attached_role_policies", "AttachedPolicies", "list_role_policies", "PolicyNames"
            )
        elif kind == "user":
            attached_op, attached_key, inline_op, inline_key = (
                "list_attached_user_policies", "AttachedPolicies", "list_user_policies", "PolicyNames"
            )
        else:
            attached_op, attached_key, inline_op, inline_key = (
                "list_attached_group_policies", "AttachedPolicies", "list_group_policies", "PolicyNames"
            )

        principal = f"{kind}/{name}"
        try:
            for policy in items(iam, attached_op, attached_key, **{kind.title() + "Name": name}):
                managed.setdefault(policy["PolicyArn"], set()).add(principal)
        except Exception as exc:
            record_error(report["errors"], f"IAM attached policies for {principal}", exc)

        try:
            for policy_name in items(iam, inline_op, inline_key, **{kind.title() + "Name": name}):
                getter = {"role": "get_role_policy", "user": "get_user_policy", "group": "get_group_policy"}[kind]
                response = getattr(iam, getter)(**{kind.title() + "Name": name, "PolicyName": policy_name})
                inline.append((policy_name, principal, "inline", response.get("PolicyDocument")))
        except Exception as exc:
            record_error(report["errors"], f"IAM inline policies for {principal}", exc)

    policy_documents: list[tuple[str, str, str, Any]] = list(inline)
    for arn, principals in managed.items():
        try:
            policy = iam.get_policy(PolicyArn=arn)["Policy"]
            version = iam.get_policy_version(
                PolicyArn=arn, VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]
            for principal in sorted(principals):
                policy_documents.append((policy.get("PolicyName", arn), principal, "managed", version.get("Document")))
        except Exception as exc:
            record_error(report["errors"], f"IAM managed policy {arn}", exc)

    for policy_name, principal, _kind, raw_document in policy_documents:
        document = decode_policy_document(raw_document)
        if document is None:
            record_error(report["errors"], f"IAM policy document {policy_name}", ValueError("Unreadable policy document"))
            continue
        report["iam"]["policy_documents_scanned"] += 1
        report["iam"]["findings"].extend(wildcard_findings(document, policy_name, principal))


def new_report(account: str, region: str) -> dict[str, Any]:
    return {
        "account": account,
        "region": region,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "cost_candidates": {
            "stopped_ec2": [],
            "unattached_ebs": [],
            "unassociated_eips": [],
            "stopped_rds": [],
        },
        "untagged": [],
        "iam": {"policy_documents_scanned": 0, "findings": []},
        "errors": [],
    }


def render_report(report: dict[str, Any]) -> str:
    candidates = report["cost_candidates"]
    untagged = report["untagged"]
    iam_findings = report["iam"]["findings"]
    critical = sum(finding["severity"] == "critical" for finding in iam_findings)
    review = len(iam_findings) - critical
    ebs_gib = sum(item["size_gib"] for item in candidates["unattached_ebs"])

    lines = [
        "# AWS cost and security audit",
        "",
        f"- **Account:** `{report['account']}`",
        f"- **Region checked:** `{report['region']}` (IAM is account-wide)",
        f"- **Generated:** {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"- **Cost review candidates:** {sum(len(values) for values in candidates.values())}",
        f"- **Unattached EBS:** {len(candidates['unattached_ebs'])} volume(s), {ebs_gib} GiB total",
        f"- **Stopped compute:** {len(candidates['stopped_ec2'])} EC2 instance(s), {len(candidates['stopped_rds'])} RDS instance(s)",
        f"- **Unassociated Elastic IPs:** {len(candidates['unassociated_eips'])}",
        f"- **Untagged resources:** {len(untagged)}",
        f"- **IAM wildcard findings:** {critical} critical, {review} for review across {report['iam']['policy_documents_scanned']} policy document attachment(s)",
        f"- **Checks with errors:** {len(report['errors'])}",
        "",
        "## Cost review candidates",
        "",
        "These are indicators to review, not automatic deletion recommendations or dollar estimates.",
        "",
    ]

    sections = [
        ("Stopped EC2 instances", candidates["stopped_ec2"], lambda item: f"`{item['id']}` ({item['type']})"),
        ("Unattached EBS volumes", candidates["unattached_ebs"], lambda item: f"`{item['id']}` ({item['size_gib']} GiB)"),
        ("Unassociated Elastic IPs", candidates["unassociated_eips"], lambda item: f"`{item['id']}` ({item['public_ip']})"),
        ("Stopped RDS instances", candidates["stopped_rds"], lambda item: f"`{item['id']}` ({item['engine']})"),
    ]
    for title, values, formatter in sections:
        lines.append(f"### {title}")
        if values:
            lines.extend(f"- {formatter(item)}" for item in values)
        else:
            lines.append("- None found")
        lines.append("")

    lines.extend(["## IAM policy review", ""])
    if iam_findings:
        for finding in iam_findings:
            lines.append(
                f"- **{finding['severity'].upper()}** `{finding['principal']}` — policy `{finding['policy']}`, statement `{finding['statement']}`: {finding['reason']} (matched: `{finding['actions']}`)"
            )
    else:
        lines.append("- No matching wildcard grants found in the policy documents that could be read.")
    lines.extend(["", "## Untagged resources", ""])
    if untagged:
        for item in untagged:
            lines.append(f"- {item['type']}: `{item['id']}`")
    else:
        lines.append("- None found")

    lines.extend(["", "## Scan limitations", ""])
    lines.append("- The regional resource checks cover EC2 instances, EBS volumes, Elastic IPs, and RDS DB instances. Run once per region you want to review.")
    lines.append("- Untagged means the resource has no tags. This does not validate required tag keys or tag values.")
    lines.append("- Stopped instances and unattached resources can be intentional. Review ownership and dependencies before changing anything.")
    lines.append("- IAM checks flag selected wildcard grants and `NotAction`/`NotResource` statements. They do not calculate effective permissions, evaluate conditions, or replace IAM Access Analyzer and a human review.")
    lines.append("- No dollar estimate or utilization analysis is included; use Cost Explorer and monitoring metrics for those.")

    if report["errors"]:
        lines.extend(["", "## Checks that could not be completed", ""])
        lines.extend(f"- {item['check']}: `{item['error']}`" for item in report["errors"])
        lines.append("- Findings may be incomplete. Review the role's read permissions and rerun.")
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a read-only AWS cost and security audit report.")
    parser.add_argument("--profile", help="AWS shared-config profile to use")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
                        help="AWS region to scan (defaults to AWS_REGION/AWS_DEFAULT_REGION or profile config)")
    parser.add_argument("--output", default="-", help="Report path; defaults to stdout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        import boto3
    except ImportError:
        print("boto3 is required. Install dependencies with: python -m pip install -r requirements.txt", file=sys.stderr)
        return 2

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        region = args.region or session.region_name
        if not region:
            print("No AWS region configured. Pass --region or configure a default region in your AWS profile.", file=sys.stderr)
            return 2
        account = session.client("sts").get_caller_identity().get("Account", "unknown")
    except Exception as exc:
        print(f"Could not create an AWS session: {exc}", file=sys.stderr)
        return 2

    report = new_report(account, region)
    scan_regional_resources(session, region, report)
    scan_iam(session, report)
    rendered = render_report(report)
    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        try:
            Path(args.output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"Could not write report to {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"Audit report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
