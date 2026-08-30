"""
AWS SQS queue policy analysis.

This module contains functions for analyzing SQS queues and their resource policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Set, Union

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_sqs.client import SQSClient

from .helpers import get_all_regions
from .policy_documents import (
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    has_not_principal,
    normalize_statements,
    read_principal,
)

logger = logging.getLogger(__name__)

# Error codes meaning a queue no longer exists.
#
# A queue deleted between `list_queues` and `get_queue_attributes` is the only
# benign reason that read fails: the queue is gone, so it holds no policy and can
# grant nobody access. Every other failure is a read Headroom could not complete
# and must not report as an absence of findings.
QUEUE_GONE_ERROR_CODES = frozenset({
    "AWS.SimpleQueueService.NonExistentQueue",
    "QueueDoesNotExist",
})


ActionsType = Union[str, List[str]]


@dataclass
class SQSQueuePolicyAnalysis:
    """
    Analysis of an SQS queue's resource policy.

    Attributes:
        queue_url: URL of the SQS queue
        queue_arn: ARN of the SQS queue
        region: AWS region where queue exists
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
        has_non_account_principals: True if the policy grants to a principal
            type carrying no account ID, which no allowlist can preserve
        actions_by_account: Dict mapping account IDs to sets of allowed actions
    """
    queue_url: str
    queue_arn: str
    region: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]


def _normalize_actions(actions: ActionsType) -> Set[str]:
    """
    Normalize action field to a set of action strings.

    Args:
        actions: Action field from policy statement (string or list)

    Returns:
        Set of action strings
    """
    if isinstance(actions, str):
        return {actions}
    return set(actions)


def _analyze_queue_policy(
    queue_url: str,
    queue_arn: str,
    region: str,
    policy_json: str,
    org_account_ids: Set[str]
) -> SQSQueuePolicyAnalysis:
    """
    Analyze a single queue's resource policy.

    Args:
        queue_url: Queue URL
        queue_arn: Queue ARN
        region: AWS region
        policy_json: Policy JSON string
        org_account_ids: Set of organization account IDs to exclude

    Returns:
        SQSQueuePolicyAnalysis result

    Raises:
        json.JSONDecodeError: If the policy is not valid JSON
        UnknownPrincipalTypeError: If a statement names a principal key AWS
            does not document
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    policy = json.loads(policy_json)
    third_party_account_ids: Set[str] = set()
    actions_by_account: Dict[str, Set[str]] = {}
    has_wildcard_principal = False
    has_non_account_principals = False

    statements = normalize_statements(policy, f"Queue {queue_arn} in {region}")

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        # An Allow with NotPrincipal reaches everyone it does not name,
        # which is what the wildcard flag records
        if has_not_principal(statement):
            has_wildcard_principal = True
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        reading = read_principal(
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, f"Queue {queue_arn} in {region}"
        )

        has_wildcard_principal = has_wildcard_principal or reading.has_wildcard
        has_non_account_principals = (
            has_non_account_principals or reading.has_non_account_principals
        )

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in reading.account_ids:
            if account_id in org_account_ids:
                continue
            third_party_account_ids.add(account_id)
            if account_id not in actions_by_account:
                actions_by_account[account_id] = set()
            actions_by_account[account_id].update(actions)

    return SQSQueuePolicyAnalysis(
        queue_url=queue_url,
        queue_arn=queue_arn,
        region=region,
        third_party_account_ids=third_party_account_ids,
        has_wildcard_principal=has_wildcard_principal,
        has_non_account_principals=has_non_account_principals,
        actions_by_account=actions_by_account,
    )


def _analyze_queues_in_region(
    session: Session,
    region: str,
    org_account_ids: Set[str]
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queues in a specific region.

    A read that fails aborts the run rather than returning an empty list.
    Returning nothing would be indistinguishable from a region that genuinely
    holds no queues with third-party access, and these results populate
    `sqs_third_party_access_account_ids_allowlist`, so the generated RCP would
    omit every partner whose queues live only in the unreadable region and deny
    them on deploy.

    This assumes the `Headroom` role is exempt from region-allowlist SCPs, which
    makes an `AccessDenied` here a genuine permissions gap rather than an
    expected regional block. See documentation/SETUP.md.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze
        org_account_ids: Set of organization account IDs to exclude

    Returns:
        List of SQSQueuePolicyAnalysis results for queues with policies

    Raises:
        ClientError: If listing queues, or reading a queue's attributes for any
            reason other than the queue having been deleted mid-scan, fails
        json.JSONDecodeError: If a queue's policy is not valid JSON
        UnknownPrincipalTypeError: If a queue policy names a principal key AWS
            does not document
    """
    sqs_client: SQSClient = session.client("sqs", region_name=region)
    results: List[SQSQueuePolicyAnalysis] = []

    try:
        paginator = sqs_client.get_paginator("list_queues")

        for page in paginator.paginate():
            queue_urls = page.get("QueueUrls", [])

            for queue_url in queue_urls:
                try:
                    attrs = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["Policy", "QueueArn"]
                    )
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code in QUEUE_GONE_ERROR_CODES:
                        logger.debug(
                            f"Queue {queue_url} in {region} was deleted during the "
                            "scan, skipping"
                        )
                        continue
                    raise

                attributes = attrs.get("Attributes", {})
                policy_json = attributes.get("Policy")
                queue_arn = attributes.get("QueueArn", "")

                if not policy_json:
                    continue

                results.append(_analyze_queue_policy(
                    queue_url=queue_url,
                    queue_arn=queue_arn,
                    region=region,
                    policy_json=policy_json,
                    org_account_ids=org_account_ids
                ))

    except ClientError as e:
        logger.error(f"Failed to analyze SQS queues in region {region}: {e}")
        raise

    return results


def analyze_sqs_queue_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queue policies across all regions.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all SQS queues
       b. Get queue attributes (Policy, QueueArn)
       c. Skip queues without policies
       d. Parse policy JSON
       e. Extract principal account IDs
       f. Identify wildcard principals
       g. Identify principals carrying no account ID, which no allowlist can
          preserve and which therefore block the account
       h. Record third-party accounts (not in org) and the actions each may
          take, admitting an account to both in one step so the two cannot
          disagree
    3. Return all results with third-party access or wildcards

    Args:
        session: boto3.Session for the target account
        org_account_ids: Set of organization account IDs to exclude from results

    Returns:
        List of SQSQueuePolicyAnalysis results

    Raises:
        ClientError: If any region's queues cannot be read
        json.JSONDecodeError: If any queue's policy is not valid JSON
        UnknownPrincipalTypeError: If any queue policy names a principal key AWS
            does not document
    """
    all_results: List[SQSQueuePolicyAnalysis] = []
    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing SQS queues in {region}")
        regional_results = _analyze_queues_in_region(session, region, org_account_ids)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} SQS queues with policies "
        f"across {len(regions)} regions"
    )
    return all_results
