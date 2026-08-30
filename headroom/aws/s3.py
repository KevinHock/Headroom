"""
AWS S3 bucket policy analysis.

This module contains functions for analyzing S3 buckets and their resource policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client

from .helpers import paginate
from .policy_documents import (
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    has_not_principal,
    normalize_statements,
    read_principal,
)

logger = logging.getLogger(__name__)


@dataclass
class S3BucketPolicyAnalysis:
    """
    Analysis of an S3 bucket's resource policy.

    Attributes:
        bucket_name: Name of the S3 bucket
        bucket_arn: ARN of the S3 bucket
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
        has_non_account_principals: True if policy has Federated/CanonicalUser principals
        actions_by_account: Dict mapping account IDs to sets of allowed actions
    """
    bucket_name: str
    bucket_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]


def _normalize_actions(action: Any) -> Set[str]:
    """
    Normalize action field to a set of action strings.

    Args:
        action: Action field from policy statement (can be string or list)

    Returns:
        Set of action strings
    """
    if isinstance(action, str):
        return {action}
    elif isinstance(action, list):
        return set(action)
    return set()


def analyze_s3_bucket_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[S3BucketPolicyAnalysis]:
    """
    Analyze all S3 bucket policies and identify third-party account principals.

    Examines the resource policy (bucket policy) of each S3 bucket
    and identifies account IDs that are not part of the organization.

    Algorithm:
    1. List all S3 buckets via list_buckets() (paginated)
    2. For each bucket:
       a. Get bucket policy via get_bucket_policy()
       b. Parse policy JSON
       c. Extract AWS principals from statements
       d. Identify third-party accounts (not in org)
       e. Track which actions each third-party account can perform
       f. Detect wildcard principals, and principals carrying no account ID
    3. Return analysis results for buckets with a finding

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of S3BucketPolicyAnalysis for buckets with third-party accounts or wildcards

    Raises:
        MalformedPolicyError: If a Statement is neither an object nor a list
        UnknownPrincipalTypeError: If a bucket policy names a principal key
            AWS does not document
    """
    s3_client: S3Client = session.client("s3")
    results: List[S3BucketPolicyAnalysis] = []

    # Materialized rather than streamed so that a failure on any page is
    # raised here, where it is reported as the listing failure it is, rather
    # than inside the loop where the bucket-policy handler would catch it.
    try:
        pages = list(paginate(s3_client, "list_buckets"))
    except ClientError as e:
        logger.error(f"Failed to list S3 buckets from AWS API: {e}")
        raise

    for bucket in [bucket for page in pages for bucket in page.get("Buckets", [])]:
        bucket_name = bucket["Name"]
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response["Policy"]
            policy = json.loads(policy_str)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                logger.debug(f"Bucket '{bucket_name}' has no bucket policy, skipping")
                continue
            else:
                logger.error(f"Failed to get bucket policy for '{bucket_name}': {e}")
                raise

        third_party_accounts: Set[str] = set()
        has_wildcard = False
        has_non_account_principals = False
        actions_by_account: Dict[str, Set[str]] = {}

        statements = normalize_statements(policy, f"Bucket '{bucket_name}'")

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            # An Allow with NotPrincipal reaches everyone it does not name,
            # which is what the wildcard flag records
            if has_not_principal(statement):
                has_wildcard = True
                continue

            principal = statement.get("Principal")
            if not principal:
                continue

            reading = read_principal(
                principal, RESOURCE_POLICY_PRINCIPAL_TYPES, f"Bucket '{bucket_name}'"
            )

            has_wildcard = has_wildcard or reading.has_wildcard
            has_non_account_principals = (
                has_non_account_principals or reading.has_non_account_principals
            )

            account_ids = reading.account_ids
            actions = _normalize_actions(statement.get("Action", []))

            for account_id in account_ids:
                if account_id not in org_account_ids:
                    third_party_accounts.add(account_id)
                    if account_id not in actions_by_account:
                        actions_by_account[account_id] = set()
                    actions_by_account[account_id].update(actions)

        if third_party_accounts or has_wildcard or has_non_account_principals:
            results.append(S3BucketPolicyAnalysis(
                bucket_name=bucket_name,
                bucket_arn=bucket_arn,
                third_party_account_ids=third_party_accounts,
                has_wildcard_principal=has_wildcard,
                has_non_account_principals=has_non_account_principals,
                actions_by_account=actions_by_account
            ))

    return results
