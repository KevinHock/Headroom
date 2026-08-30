"""
AWS KMS key policy analysis.

This module contains functions for analyzing KMS key policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.type_defs import KeyListEntryTypeDef

from .helpers import get_all_regions, paginate
from .policy_documents import (
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    has_not_principal,
    normalize_statements,
    read_principal,
)

logger = logging.getLogger(__name__)


@dataclass
class KMSKeyPolicyAnalysis:
    """
    Analysis of a KMS key's resource policy.

    Attributes:
        key_id: KMS key ID
        key_arn: ARN of the KMS key
        region: AWS region where key exists
        third_party_account_ids: Set of account IDs not in the organization
        actions_by_account: Mapping of account ID to list of KMS actions allowed
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
        has_non_account_principals: True if the policy grants to a principal
            type carrying no account ID, which no allowlist can preserve
    """
    key_id: str
    key_arn: str
    region: str
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False
    has_non_account_principals: bool = False


def _normalize_actions(action: Any) -> List[str]:
    """
    Normalize action field to list of strings.

    Args:
        action: Action field from policy statement (can be string or list)

    Returns:
        List of action strings
    """
    if isinstance(action, str):
        return [action]
    return list(action)


def _analyze_key_in_region(
    kms_client: KMSClient,
    key: KeyListEntryTypeDef,
    region: str,
    org_account_ids: Set[str]
) -> KMSKeyPolicyAnalysis:
    """
    Analyze a single KMS key's policy.

    Args:
        kms_client: Boto3 KMS client
        key: Key dict from list_keys
        region: AWS region
        org_account_ids: Set of all account IDs in the organization

    Returns:
        KMSKeyPolicyAnalysis result for this key

    Raises:
        UnknownPrincipalTypeError: If a statement names a principal key AWS
            does not document
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    key_id = key["KeyId"]
    key_arn = key["KeyArn"]

    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False
    has_non_account_principals = False

    try:
        response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
        policy_text = response.get("Policy", "{}")
        policy = json.loads(policy_text)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NotFoundException":
            logger.debug(f"No policy found for key {key_id} in {region}")
            return KMSKeyPolicyAnalysis(
                key_id=key_id,
                key_arn=key_arn,
                region=region,
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=False
            )
        raise

    statements = normalize_statements(policy, f"Key '{key_id}' in {region}")

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
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, f"Key '{key_id}' in {region}"
        )

        has_wildcard = has_wildcard or reading.has_wildcard
        has_non_account_principals = (
            has_non_account_principals or reading.has_non_account_principals
        )
        account_ids = reading.account_ids

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id in org_account_ids:
                continue

            third_party_accounts.add(account_id)
            actions_by_account[account_id].update(actions)

    actions_by_account_serializable = {
        account_id: sorted(actions)
        for account_id, actions in actions_by_account.items()
    }

    return KMSKeyPolicyAnalysis(
        key_id=key_id,
        key_arn=key_arn,
        region=region,
        third_party_account_ids=third_party_accounts,
        actions_by_account=actions_by_account_serializable,
        has_wildcard_principal=has_wildcard,
        has_non_account_principals=has_non_account_principals
    )


def analyze_kms_key_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[KMSKeyPolicyAnalysis]:
    """
    Analyze all KMS keys in an account for third-party access.

    Examines the resource policy of each KMS key and identifies
    account IDs that are not part of the organization.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all keys via list_keys() (paginated)
       b. Get key policy via get_key_policy()
       c. Parse policy JSON
       d. Extract principals and actions
       e. Identify third-party account IDs (not in org)
       f. Track which actions each third-party account can perform
       g. Detect wildcard principals, and principals carrying no account ID
    3. Return all results across all regions

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of KMSKeyPolicyAnalysis for keys with third-party access,
        wildcards, or principals carrying no account ID

    Raises:
        ClientError: If AWS API calls fail
        UnknownPrincipalTypeError: If any key policy names a principal key AWS
            does not document
    """
    results: List[KMSKeyPolicyAnalysis] = []

    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing KMS keys in {region}")
        kms_client: KMSClient = session.client("kms", region_name=region)

        try:
            for page in paginate(kms_client, "list_keys"):
                for key in page.get("Keys", []):
                    analysis = _analyze_key_in_region(
                        kms_client,
                        key,
                        region,
                        org_account_ids
                    )

                    if analysis.third_party_account_ids or analysis.has_wildcard_principal or analysis.has_non_account_principals:
                        results.append(analysis)

        except ClientError:
            logger.error(f"Failed to analyze KMS in region {region}")
            raise

    logger.info(
        f"Analyzed KMS keys across {len(regions)} regions, "
        f"found {len(results)} keys with third-party access or wildcards"
    )
    return results
