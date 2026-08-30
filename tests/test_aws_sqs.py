"""
Tests for headroom.aws.sqs module.
"""

import json
from typing import Any

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.sqs import (
    analyze_sqs_queue_policies,
)
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)


class TestAnalyzeSQSQueuePolicies:
    """Test analyze_sqs_queue_policies function."""

    def test_single_queue_with_third_party(self) -> None:
        """Test analyzing single queue with third-party access."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"],
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].queue_url == queue_url
        assert results[0].queue_arn == queue_arn
        assert results[0].region == "us-east-1"
        assert results[0].third_party_account_ids == {"222222222222"}
        assert results[0].has_wildcard_principal is False
        assert results[0].has_non_account_principals is False
        assert "222222222222" in results[0].actions_by_account
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage", "sqs:ReceiveMessage"}

    def test_queue_with_wildcard_principal(self) -> None:
        """Test queue with wildcard principal."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/public-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:public-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:*",
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_queue_without_policy_skipped(self) -> None:
        """Test queues without policies are skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/no-policy-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:us-east-1:111111111111:no-policy-queue"
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_multiple_third_party_accounts(self) -> None:
        """Test queue with multiple third-party accounts."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/multi-party-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:multi-party-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::222222222222:root", "333333333333"]},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::444444444444:root"},
                    "Action": "sqs:ReceiveMessage",
                    "Resource": queue_arn
                }
            ]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"222222222222", "333333333333", "444444444444"}
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage"}
        assert results[0].actions_by_account["333333333333"] == {"sqs:SendMessage"}
        assert results[0].actions_by_account["444444444444"] == {"sqs:ReceiveMessage"}

    def test_an_in_organization_grantee_is_not_recorded(self) -> None:
        """
        A grant to an account inside the organization is not a finding.

        The queue is still returned for the third party it also grants to,
        but the in-organization account belongs in neither the account set
        nor the action map. Keying it into the action map is what fed
        in-organization IDs into `actions_by_third_party_account` and
        `queues_by_third_party_account`, whose names promise the opposite.
        """
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/shared-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:shared-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::555555555555:root"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "sqs:ReceiveMessage",
                    "Resource": queue_arn
                }
            ]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111", "555555555555"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"222222222222"}
        assert results[0].actions_by_account == {"222222222222": {"sqs:ReceiveMessage"}}

    def test_multi_region_queues(self) -> None:
        """Test analyzing queues across multiple regions."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        mock_sqs_clients = {}
        for region in ["us-east-1", "us-west-2"]:
            mock_sqs_clients[region] = MagicMock()

        def client_factory(service: str, **kwargs: dict) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            return mock_sqs_clients[kwargs["region_name"]]  # type: ignore[index]

        mock_session.client.side_effect = client_factory

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        queue_url_east = "https://sqs.us-east-1.amazonaws.com/111111111111/queue-east"
        queue_arn_east = "arn:aws:sqs:us-east-1:111111111111:queue-east"

        queue_url_west = "https://sqs.us-west-2.amazonaws.com/111111111111/queue-west"
        queue_arn_west = "arn:aws:sqs:us-west-2:111111111111:queue-west"

        paginator_east = MagicMock()
        paginator_east.paginate.return_value = [{"QueueUrls": [queue_url_east]}]
        mock_sqs_clients["us-east-1"].get_paginator.return_value = paginator_east

        paginator_west = MagicMock()
        paginator_west.paginate.return_value = [{"QueueUrls": [queue_url_west]}]
        mock_sqs_clients["us-west-2"].get_paginator.return_value = paginator_west

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:*",
                "Resource": "*"
            }]
        }

        mock_sqs_clients["us-east-1"].get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn_east
            }
        }

        mock_sqs_clients["us-west-2"].get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn_west
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 2
        assert results[0].region == "us-east-1"
        assert results[1].region == "us-west-2"

    def test_access_denied_in_one_region_aborts_the_run(self) -> None:
        """
        AccessDenied in one region aborts the whole analysis.

        The results of this check populate
        `sqs_third_party_access_account_ids_allowlist`, so a region that could
        not be read is indistinguishable from a region with no third-party
        access. Continuing would emit an allowlist missing every partner whose
        queues live only in the unreadable region, and deploying that RCP would
        deny them. Headroom requires its role to be exempt from region-allowlist
        SCPs, so an AccessDenied here is a real permissions gap, not an expected
        regional block.

        us-east-1 is analyzed first, so the later region proves the abort is
        immediate rather than deferred to the end of the loop.
        """
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        mock_sqs_clients = {}
        for region in ["us-east-1", "us-west-2"]:
            mock_sqs_clients[region] = MagicMock()

        def client_factory(service: str, **kwargs: dict) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            return mock_sqs_clients[kwargs["region_name"]]  # type: ignore[index]

        mock_session.client.side_effect = client_factory

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        paginator_east = MagicMock()
        paginator_east.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )
        mock_sqs_clients["us-east-1"].get_paginator.return_value = paginator_east

        queue_url_west = "https://sqs.us-west-2.amazonaws.com/111111111111/queue-west"
        queue_arn_west = "arn:aws:sqs:us-west-2:111111111111:queue-west"

        paginator_west = MagicMock()
        paginator_west.paginate.return_value = [{"QueueUrls": [queue_url_west]}]
        mock_sqs_clients["us-west-2"].get_paginator.return_value = paginator_west

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:*",
                "Resource": queue_arn_west
            }]
        }

        mock_sqs_clients["us-west-2"].get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn_west
            }
        }

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"
        # The failure aborted before us-west-2 was touched at all.
        mock_sqs_clients["us-west-2"].get_paginator.assert_not_called()

    def test_deny_statement_ignored(self) -> None:
        """Test that Deny statements are ignored."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [queue_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "sqs:DeleteMessage",
                    "Resource": queue_arn
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn
                }
            ]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert "222222222222" in results[0].actions_by_account
        assert results[0].actions_by_account["222222222222"] == {"sqs:SendMessage"}
        assert "sqs:DeleteMessage" not in results[0].actions_by_account["222222222222"]

    def test_statement_not_as_list(self) -> None:
        """Test that Statement field as a dict (not list) is handled."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        # Statement as a dict instead of a list
        policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn
            }
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert "222222222222" in results[0].third_party_account_ids

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """A Statement of any other type aborts rather than reporting nothing."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps({"Version": "2012-10-17", "Statement": "Allow"}),
                "QueueArn": queue_arn
            }
        }

        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            analyze_sqs_queue_policies(mock_session, {"111111111111"})

    def test_missing_principal(self) -> None:
        """Test that statements without Principal are skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        # Statement without Principal
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": queue_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        org_account_ids = {"111111111111"}
        results = analyze_sqs_queue_policies(mock_session, org_account_ids)

        # Should still return a result, but with no third-party accounts
        assert len(results) == 1
        assert len(results[0].third_party_account_ids) == 0
        assert not results[0].has_wildcard_principal
        assert not results[0].has_non_account_principals

    def _single_region_session(self) -> tuple[MagicMock, MagicMock]:
        """Build a session mock wired to one region and return (session, sqs_client)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }
        return mock_session, mock_sqs_client

    def test_listing_queues_raises_on_access_denied(self) -> None:
        """
        AccessDenied while listing queues raises rather than returning nothing.

        Returning an empty list would report the region as having no queues with
        third-party access, which is the same value a genuinely empty region
        produces. Nothing downstream can tell the two apart.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )
        mock_sqs_client.get_paginator.return_value = paginator

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_listing_queues_raises_on_service_error(self) -> None:
        """A transient service error is not silently reinterpreted as zero findings."""
        mock_session, mock_sqs_client = self._single_region_session()

        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable"}},
            "ListQueues"
        )
        mock_sqs_client.get_paginator.return_value = paginator

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert exc_info.value.response["Error"]["Code"] == "ServiceUnavailable"

    def test_get_paginator_failure_propagates(self) -> None:
        """
        A failure building the paginator propagates.

        `get_paginator` issues no API call, so this is defensive rather than
        reachable in practice. It is pinned so the path cannot regress into
        swallowing if that ever changes.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        mock_sqs_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "ListQueues"
        )

        with pytest.raises(ClientError):
            analyze_sqs_queue_policies(mock_session, {"111111111111"})

    def test_reading_queue_attributes_raises(self) -> None:
        """
        A failure reading one queue's policy aborts rather than skipping it.

        Skipping drops that queue's third-party accounts from the allowlist,
        which is the failure this check exists to prevent.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "GetQueueAttributes"
        )

        with pytest.raises(ClientError) as exc_info:
            analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_queue_deleted_during_scan_is_skipped(self) -> None:
        """
        A queue deleted between listing and reading is skipped, not fatal.

        This is the one benign reason a read fails: the queue is genuinely gone,
        so it holds no policy and can grant nobody access. Later queues are still
        analyzed, which distinguishes this from the aborting cases above.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        deleted_url = "https://sqs.us-east-1.amazonaws.com/111111111111/deleted"
        live_url = "https://sqs.us-east-1.amazonaws.com/111111111111/live"
        live_arn = "arn:aws:sqs:us-east-1:111111111111:live"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [deleted_url, live_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sqs:SendMessage",
                "Resource": live_arn
            }]
        }

        mock_sqs_client.get_queue_attributes.side_effect = [
            ClientError(
                {"Error": {"Code": "AWS.SimpleQueueService.NonExistentQueue"}},
                "GetQueueAttributes"
            ),
            {"Attributes": {"Policy": json.dumps(policy), "QueueArn": live_arn}},
        ]

        results = analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].queue_arn == live_arn
        assert results[0].third_party_account_ids == {"222222222222"}

    def test_unparseable_policy_aborts_the_run(self) -> None:
        """
        A queue policy that is not valid JSON aborts rather than being skipped.

        Skipping dropped the queue from the results, so an account whose only
        third-party grant sat in that queue parsed as having no findings and was
        cleared for the RCP - absence of evidence read as evidence of safety
        (INV-01). A policy that GetQueueAttributes returns and json cannot read
        is not an ordinary fact about the account either: SetQueueAttributes
        validates the document, so this means Headroom read the attribute wrong
        or something upstream is broken.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": "{invalid json",
                "QueueArn": queue_arn,
            }
        }

        with pytest.raises(json.JSONDecodeError):
            analyze_sqs_queue_policies(mock_session, {"111111111111"})

    def test_a_federated_principal_blocks_the_queue_rather_than_the_run(self) -> None:
        """
        A Federated principal is a finding, not a reason to stop scanning.

        It carries no account ID, so the RCP's allowlist cannot preserve its
        access - which is the same verdict `Principal: "*"` earns, and the
        blocking verdict is delivered by recording it. Aborting delivered the
        same protection for this account at the cost of every other account's
        results, and put the finding in a stack trace instead of the report.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/federated-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:federated-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::111111111111:saml-provider/Example"
                        },
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    }],
                }),
                "QueueArn": queue_arn,
            }
        }

        results = analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].third_party_account_ids == set()

    def test_a_canonical_user_blocks_the_queue_rather_than_vanishing(self) -> None:
        """
        A CanonicalUser principal is recorded, where it used to be skipped.

        Skipping dropped the queue from the results, so an account whose only
        third-party grant sat here reported no findings and took the RCP
        anyway - absence of evidence read as evidence of safety (INV-01). A
        canonical user ID maps to an account only through an API call the scan
        does not make, so no allowlist can carry it and the account is blocked.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"CanonicalUser": "d" * 64},
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    }],
                }),
                "QueueArn": queue_arn,
            }
        }

        results = analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    def test_a_queue_after_a_federated_one_is_still_read(self) -> None:
        """
        The scan reaches every queue, which is what not aborting buys.

        One queue's unallowlistable principal used to end the run, so a
        third-party grant in any queue listed after it never entered the
        allowlist and the generated RCP denied that partner on deploy.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        federated_url = "https://sqs.us-east-1.amazonaws.com/111111111111/federated-queue"
        ordinary_url = "https://sqs.us-east-1.amazonaws.com/111111111111/partner-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"QueueUrls": [federated_url, ordinary_url]}
        ]
        mock_sqs_client.get_paginator.return_value = paginator

        policies = {
            federated_url: {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::111111111111:saml-provider/Example"
                    },
                    "Action": "sqs:SendMessage",
                }],
            },
            ordinary_url: {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "999999999999"},
                    "Action": "sqs:SendMessage",
                }],
            },
        }
        mock_sqs_client.get_queue_attributes.side_effect = lambda **kwargs: {
            "Attributes": {
                "Policy": json.dumps(policies[kwargs["QueueUrl"]]),
                "QueueArn": kwargs["QueueUrl"],
            }
        }

        results = analyze_sqs_queue_policies(mock_session, {"111111111111"})

        assert len(results) == 2
        assert results[1].third_party_account_ids == {"999999999999"}

    def test_a_principal_key_aws_does_not_document_aborts(self) -> None:
        """
        An undocumented principal key still stops the run.

        AWS validates the Principal element when SetQueueAttributes stores the
        policy, so a key outside the documented four means Headroom misread the
        attribute or AWS has added a principal type nobody has modelled here.
        Recording it as a finding would state a verdict on a grant this code
        cannot read.
        """
        mock_session, mock_sqs_client = self._single_region_session()

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Kerberos": "example"},
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    }],
                }),
                "QueueArn": queue_arn,
            }
        }

        with pytest.raises(UnknownPrincipalTypeError):
            analyze_sqs_queue_policies(mock_session, {"111111111111"})


class TestPolicyGrammar:
    """Policy elements the queue analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_sqs_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "sqs": mock_sqs_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        queue_url = "https://sqs.us-east-1.amazonaws.com/111111111111/test-queue"
        queue_arn = "arn:aws:sqs:us-east-1:111111111111:test-queue"

        paginator = MagicMock()
        paginator.paginate.return_value = [{"QueueUrls": [queue_url]}]
        mock_sqs_client.get_paginator.return_value = paginator

        mock_sqs_client.get_queue_attributes.return_value = {
            "Attributes": {
                "Policy": json.dumps(policy),
                "QueueArn": queue_arn
            }
        }

        return analyze_sqs_queue_policies(mock_session, {"111111111111"})

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal grants to everyone it does not name.

        Skipping the statement for want of a Principal reported the queue
        clean, so the account kept its RCP and the grant's real audience -
        every account outside the exclusion list - lost access on apply.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a resource policy's Deny cannot
        hand access to anyone, so it must not block the RCP. This analyzer
        reports every queue carrying a policy, so the queue is still
        returned - with nothing found on it.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111111111111:test-queue"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is False
        assert results[0].third_party_account_ids == set()
