"""
Shared AWS helper utilities for region discovery, pagination, and tag matching.
"""

from collections.abc import Iterator
from typing import Any, Optional

from boto3.session import Session
from botocore.client import BaseClient
from mypy_boto3_ec2.client import EC2Client

__all__ = ["find_tag_value_as_iam_matches", "get_all_regions", "paginate"]


def get_all_regions(session: Session) -> list[str]:
    """
    Return the AWS regions that are enabled for the account.

    `describe_regions` is deliberately called with no arguments. The default
    response contains only regions the account has enabled -- those with an
    OptInStatus of `opt-in-not-required` or `opted-in` -- and omits every
    `not-opted-in` region.

    Do not pass `AllRegions=True`. It adds disabled regions to the result, and
    since every caller builds a per-region client from this list, each disabled
    region would become a doomed API call against a region the account cannot
    use. Headroom has no interest in analyzing a region that cannot hold
    resources. `test_only_enabled_regions_are_requested` pins this.

    Note that an enabled region does not guarantee the service is available
    there; handling a missing regional endpoint is the caller's concern.
    """
    ec2_client: EC2Client = session.client("ec2")
    response = ec2_client.describe_regions()
    return [region["RegionName"] for region in response["Regions"]]


def paginate(
    client: BaseClient,
    operation_name: str,
    **operation_kwargs: Any
) -> Iterator[dict[str, Any]]:
    """
    Yield pages for a paginated AWS API operation.
    """
    paginator = client.get_paginator(operation_name)
    for page in paginator.paginate(**operation_kwargs):
        yield page


def find_tag_value_as_iam_matches(
    tags: dict[str, str],
    tag_key: str,
    resource_description: str,
) -> Optional[str]:
    """
    Find a tag's value the way IAM matches it in an `aws:RequestTag` condition.

    The two halves of the match pull opposite ways, and a scan has to follow
    both. AWS matches the key name in `aws:RequestTag/<key>` without regard to
    case, so comparing the key exactly here reports a resource as violating a
    statement enforcement would allow. The value is compared with a
    case-sensitive string operator, so lowercasing it reports a resource as
    satisfying a statement enforcement would deny. This function settles the
    key; comparing the value is the caller's job, and must be exact.

    A resource carrying the key twice in cases that differ has no determinate
    answer. AWS documents the condition as matching one spelling or the other
    but not both, so guessing which one IAM lands on would invent the verdict
    for a live workload.

    Both tag checks share this because they read the same kind of tag, and
    reading it by two different rules is what conflict 5 was.

    Args:
        tags: The resource's tags
        tag_key: The tag key as the policy statement spells it
        resource_description: The resource the tags came from, named in the
            error, for example "Instance i-11111111111111111"

    Returns:
        The tag's value, or None when the resource does not carry the key

    Raises:
        RuntimeError: If the resource carries the key more than once, in cases
            that differ
    """
    wanted_key = tag_key.lower()
    matches = {key: value for key, value in tags.items() if key.lower() == wanted_key}

    if len(matches) > 1:
        raise RuntimeError(
            f"{resource_description} carries {tag_key} more than once in cases "
            f"that differ ({', '.join(sorted(matches))}). IAM matches the tag "
            f"key in aws:RequestTag without regard to case, so every one of "
            f"them matches the statement's condition key while at most one "
            f"value can - which AWS documents as matching one spelling or the "
            f"other, but not both. Which verdict applies to this resource "
            f"cannot be determined, and guessing would misreport whether the "
            f"policy is safe to attach here."
        )

    return next(iter(matches.values()), None)
