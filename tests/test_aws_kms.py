"""Tests for headroom.aws.kms module."""

import json
from typing import Any

import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.kms import analyze_kms_key_policies
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)


class TestAnalyzeKmsKeyPolicies:
    """Test analyze_kms_key_policies function."""

    def test_analyze_keys_with_third_party_access(self) -> None:
        """Test successful analysis with keys having third-party access."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-123",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-123"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":["kms:Decrypt","kms:DescribeKey"],"Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111", "222222222222"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].key_id == "key-123"
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == ["kms:Decrypt", "kms:DescribeKey"]
        assert results[0].has_wildcard_principal is False

    def test_analyze_keys_with_wildcard(self) -> None:
        """Test analysis with key having wildcard principal."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-wildcard",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-wildcard"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_analyze_keys_without_policy(self) -> None:
        """Test analysis when key has no policy."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-no-policy",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-no-policy"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        error_response = {"Error": {"Code": "NotFoundException"}}
        mock_kms_client.get_key_policy.side_effect = ClientError(error_response, "GetKeyPolicy")  # type: ignore[arg-type]

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_keys_org_only(self) -> None:
        """Test analysis when keys only have org access (no findings)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-org-only",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-org-only"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_analyze_keys_multiple_actions(self) -> None:
        """Test tracking multiple actions per account."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-multiple",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-multiple"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey"],"Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert len(results[0].actions_by_account["999999999999"]) == 3
        assert "kms:Decrypt" in results[0].actions_by_account["999999999999"]
        assert "kms:Encrypt" in results[0].actions_by_account["999999999999"]
        assert "kms:GenerateDataKey" in results[0].actions_by_account["999999999999"]

    def test_analyze_keys_multiple_third_party_accounts(self) -> None:
        """Test key with multiple third-party accounts."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-multi-account",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-multi-account"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::999999999999:root","arn:aws:iam::888888888888:root"]},"Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}
        results = analyze_kms_key_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999", "888888888888"}
        assert "999999999999" in results[0].actions_by_account
        assert "888888888888" in results[0].actions_by_account

    def test_a_federated_principal_blocks_the_key_rather_than_the_run(self) -> None:
        """
        A Federated principal is recorded as a finding, not raised.

        A SAML provider ARN carries twelve digits, but they name the account
        hosting the provider rather than the caller, so no allowlist keyed on
        aws:PrincipalAccount can preserve the grant. That blocks the account;
        it does not mean the other keys cannot be read.
        """
        mock_session, mock_kms_client = self._single_region_session()

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-federated",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-federated"
                    }
                ]
            }
        ]
        mock_kms_client.get_paginator.return_value = keys_paginator

        mock_kms_client.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::333333333333:saml-provider/Example"
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }],
            })
        }

        results = analyze_kms_key_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].third_party_account_ids == set()

    def test_a_canonical_user_blocks_the_key(self) -> None:
        """A canonical user ID maps to no account the allowlist can carry."""
        mock_session, mock_kms_client = self._single_region_session()

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-canonical",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-canonical"
                    }
                ]
            }
        ]
        mock_kms_client.get_paginator.return_value = keys_paginator

        mock_kms_client.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"CanonicalUser": "d" * 64},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }],
            })
        }

        results = analyze_kms_key_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    @staticmethod
    def _single_region_session() -> tuple[MagicMock, MagicMock]:
        """Build a session mock wired to one region and return (session, kms_client)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }
        return mock_session, mock_kms_client

    def test_analyze_kms_policies_unknown_principal_type(self) -> None:
        """Test analyze_kms_key_policies with unknown principal type."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-unknown",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-unknown"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"UnknownType":"value"},"Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            analyze_kms_key_policies(mock_session, org_account_ids)
        assert "UnknownType" in str(exc_info.value)

    def test_analyze_kms_policies_deny_statement(self) -> None:
        """Test analyze_kms_key_policies with Deny statement (should be skipped)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-deny",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-deny"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        results = analyze_kms_key_policies(mock_session, org_account_ids)

        # Keys with only Deny statements don't have third-party access or wildcards, so no result
        assert len(results) == 0

    def test_analyze_kms_policies_no_principal(self) -> None:
        """Test analyze_kms_key_policies with statement missing Principal field."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-no-principal",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-no-principal"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator

        policy_response = {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}'
        }
        mock_kms_client.get_key_policy.return_value = policy_response

        org_account_ids = {"111111111111"}

        results = analyze_kms_key_policies(mock_session, org_account_ids)

        # Keys without Principal don't have third-party access or wildcards, so no result
        assert len(results) == 0

    def test_analyze_kms_policies_client_error(self) -> None:
        """Test analyze_kms_key_policies with ClientError during analysis."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListKeys"
        )

        mock_kms_client.get_paginator.return_value = keys_paginator

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_kms_key_policies(mock_session, org_account_ids)

    def test_analyze_kms_policies_get_policy_error(self) -> None:
        """Test analyze_kms_key_policies with ClientError when getting key policy."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        def mock_client(service: str, **kwargs: str) -> MagicMock:
            clients = {
                "ec2": mock_ec2_client,
                "kms": mock_kms_client,
            }
            return clients[service]

        mock_session.client = mock_client

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-error",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-error"
                    }
                ]
            }
        ]

        mock_kms_client.get_paginator.return_value = keys_paginator
        mock_kms_client.get_key_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetKeyPolicy"
        )

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError) as exc_info:
            analyze_kms_key_policies(mock_session, org_account_ids)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


class TestPolicyGrammar:
    """Policy elements the key analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_kms_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "kms": mock_kms_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        keys_paginator = MagicMock()
        keys_paginator.paginate.return_value = [
            {
                "Keys": [
                    {
                        "KeyId": "key-123",
                        "KeyArn": "arn:aws:kms:us-east-1:111111111111:key/key-123"
                    }
                ]
            }
        ]
        mock_kms_client.get_paginator.return_value = keys_paginator
        mock_kms_client.get_key_policy.return_value = {"Policy": json.dumps(policy)}

        return analyze_kms_key_policies(mock_session, {"111111111111"})

    def test_lone_statement_object_is_analyzed(self) -> None:
        """The third party in a lone statement object is found, not missed."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*"
            }
        })

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == ["kms:Decrypt"]

    def test_statement_neither_object_nor_list_raises(self) -> None:
        """A Statement of any other type aborts rather than reporting nothing."""
        with pytest.raises(MalformedPolicyError, match="Statement of type str"):
            self._analyze({"Version": "2012-10-17", "Statement": "Allow"})

    def test_not_principal_is_read_as_a_wildcard(self) -> None:
        """
        An Allow with NotPrincipal grants to everyone it does not name.

        Skipping the statement for want of a Principal reported the resource
        clean, so the account kept its RCP and the grant's real audience -
        every account outside the exclusion list - lost access on apply.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*"
            }
        })

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True
        assert results[0].third_party_account_ids == set()

    def test_deny_with_not_principal_is_not_a_wildcard(self) -> None:
        """
        Deny with NotPrincipal restricts rather than grants.

        It is the form AWS recommends, and a resource policy's Deny cannot
        hand access to anyone, so it must not block the RCP.
        """
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "kms:Decrypt",
                "Resource": "*"
            }
        })

        assert results == []
