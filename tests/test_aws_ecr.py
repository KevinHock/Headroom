"""
Tests for headroom.aws.ecr module.
"""

import json

import pytest
from typing import Any
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from headroom.aws.ecr import (
    analyze_ecr_repository_policies,
    _normalize_actions,
)
from headroom.aws.policy_documents import (
    MalformedPolicyError,
    UnknownPrincipalTypeError,
)


class TestNormalizeActions:
    """Test _normalize_actions function."""

    def test_string_action(self) -> None:
        """Test normalizing string action."""
        assert _normalize_actions("ecr:GetDownloadUrlForLayer") == ["ecr:GetDownloadUrlForLayer"]

    def test_list_actions(self) -> None:
        """Test normalizing list of actions."""
        actions = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        assert _normalize_actions(actions) == actions

    def test_none_action(self) -> None:
        """Test normalizing None."""
        assert _normalize_actions(None) == []

    def test_empty_list(self) -> None:
        """Test normalizing empty list."""
        assert _normalize_actions([]) == []


class TestAnalyzeECRRepositoryPolicies:
    """Test analyze_ecr_repository_policies function."""

    def test_successful_analysis(self) -> None:
        """Test successful ECR repository policy analysis."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999999999999:root"
                    },
                    "Action": [
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage"
                    ]
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].repository_name == "test-repo"
        assert results[0].third_party_account_ids == {"999999999999"}
        assert "999999999999" in results[0].actions_by_account
        assert "ecr:GetDownloadUrlForLayer" in results[0].actions_by_account["999999999999"]
        assert "ecr:BatchGetImage" in results[0].actions_by_account["999999999999"]

    def test_repository_without_policy(self) -> None:
        """Test repository without policy is skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        from botocore.exceptions import ClientError
        error_response: Any = {"Error": {"Code": "RepositoryPolicyNotFoundException"}}
        mock_ecr_client.get_repository_policy.side_effect = ClientError(
            error_response, "GetRepositoryPolicy"
        )

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_wildcard_principal_detection(self) -> None:
        """Test detection of wildcard principals."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "public-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/public-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].has_wildcard_principal is True

    def test_org_account_filtered_out(self) -> None:
        """Test organization accounts are filtered out."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "internal-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/internal-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::222222222222:root"
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_actions_deduplicated_per_account(self) -> None:
        """Ensure duplicate actions are not repeated for an account."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "dedup-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/dedup-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999999999999:root"
                    },
                    "Action": [
                        "ecr:BatchGetImage",
                        "ecr:BatchGetImage"
                    ]
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 1
        actions = results[0].actions_by_account["999999999999"]
        assert actions == ["ecr:BatchGetImage"]

    def test_multiple_repositories_multiple_regions(self) -> None:
        """Test analysis across multiple repositories and regions."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        ecr_clients = {}
        for region in ["us-east-1", "us-west-2"]:
            mock_ecr_client = MagicMock()
            repository_paginator = MagicMock()
            repository_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": f"repo-{region}",
                            "repositoryArn": f"arn:aws:ecr:{region}:111111111111:repository/repo-{region}"
                        }
                    ]
                }
            ]
            mock_ecr_client.get_paginator.return_value = repository_paginator

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::999999999999:root"
                        },
                        "Action": "ecr:BatchGetImage"
                    }
                ]
            }

            mock_ecr_client.get_repository_policy.return_value = {
                "policyText": json.dumps(policy)
            }
            ecr_clients[region] = mock_ecr_client

        def client_side_effect(service: str, **kwargs: Any) -> object:
            if service == "ec2":
                return mock_ec2_client
            region = kwargs.get("region_name", "us-east-1")
            return ecr_clients.get(region)

        mock_session.client.side_effect = client_side_effect

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 2
        regions_found = {r.region for r in results}
        assert regions_found == {"us-east-1", "us-west-2"}

    def test_mixed_third_party_and_org_accounts(self) -> None:
        """Test policy with both third-party and org accounts."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "mixed-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/mixed-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::222222222222:root",
                            "arn:aws:iam::999999999999:root"
                        ]
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111", "222222222222"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}

    def test_deny_statement_ignored(self) -> None:
        """Test that Deny statements are ignored."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": "arn:aws:iam::999999999999:root"
                    },
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_policy_with_no_principal(self) -> None:
        """Test that statements without principals are skipped."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ecr:*"
                }
            ]
        }

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        org_account_ids = {"111111111111"}

        results = analyze_ecr_repository_policies(mock_session, org_account_ids)

        assert len(results) == 0

    def test_get_repository_policy_error(self) -> None:
        """Test that non-RepositoryPolicyNotFoundException errors are raised."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]

        mock_ecr_client.get_paginator.return_value = repository_paginator

        error_response: Any = {"Error": {"Code": "AccessDeniedException"}}
        mock_ecr_client.get_repository_policy.side_effect = ClientError(
            error_response, "GetRepositoryPolicy"
        )

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_ecr_repository_policies(mock_session, org_account_ids)

    def test_ecr_client_error(self) -> None:
        """Test that ECR client errors during describe_repositories are raised."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        error_response: Any = {"Error": {"Code": "AccessDeniedException"}}
        repository_paginator = MagicMock()
        repository_paginator.paginate.side_effect = ClientError(
            error_response, "DescribeRepositories"
        )

        mock_ecr_client.get_paginator.return_value = repository_paginator

        org_account_ids = {"111111111111"}

        with pytest.raises(ClientError):
            analyze_ecr_repository_policies(mock_session, org_account_ids)

    def test_a_federated_principal_blocks_the_repository_rather_than_the_run(self) -> None:
        """
        A Federated principal is recorded as a finding, not raised.

        It carries no account ID, so the allowlist cannot preserve its access
        and the account must not take this RCP. Recording says exactly that
        and leaves every other account's repositories still scannable;
        aborting said it by throwing away the run.
        """
        mock_session, mock_ecr_client = self._single_region_session()

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "federated-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/federated-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::111111111111:saml-provider/Example"
                        },
                        "Action": "ecr:*"
                    }
                ]
            })
        }

        results = analyze_ecr_repository_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].has_non_account_principals is True
        assert results[0].third_party_account_ids == set()

    def test_a_canonical_user_blocks_the_repository(self) -> None:
        """A canonical user ID maps to no account the allowlist can carry."""
        mock_session, mock_ecr_client = self._single_region_session()

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "canonical-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/canonical-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"CanonicalUser": "d" * 64},
                        "Action": "ecr:*"
                    }
                ]
            })
        }

        results = analyze_ecr_repository_policies(mock_session, {"111111111111"})

        assert len(results) == 1
        assert results[0].has_non_account_principals is True

    def test_a_principal_key_aws_does_not_document_aborts(self) -> None:
        """
        An undocumented principal key still stops the run.

        AWS validates the Principal element when it stores a repository
        policy, so a key outside the documented four means the document was
        misread or names a principal type nobody has modelled here.
        """
        mock_session, mock_ecr_client = self._single_region_session()

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "odd-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/odd-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator

        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Kerberos": "example"},
                        "Action": "ecr:*"
                    }
                ]
            })
        }

        with pytest.raises(UnknownPrincipalTypeError):
            analyze_ecr_repository_policies(mock_session, {"111111111111"})

    @staticmethod
    def _single_region_session() -> tuple[MagicMock, MagicMock]:
        """Build a session mock wired to one region and return (session, ecr_client)."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }
        return mock_session, mock_ecr_client


class TestPolicyGrammar:
    """Policy elements the repository analyzer must read the way IAM does."""

    @staticmethod
    def _analyze(policy: Any) -> Any:
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ecr_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "ecr": mock_ecr_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        repository_paginator = MagicMock()
        repository_paginator.paginate.return_value = [
            {
                "repositories": [
                    {
                        "repositoryName": "test-repo",
                        "repositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/test-repo"
                    }
                ]
            }
        ]
        mock_ecr_client.get_paginator.return_value = repository_paginator
        mock_ecr_client.get_repository_policy.return_value = {
            "policyText": json.dumps(policy)
        }

        return analyze_ecr_repository_policies(mock_session, {"111111111111"})

    def test_lone_statement_object_is_analyzed(self) -> None:
        """The third party in a lone statement object is found, not missed."""
        results = self._analyze({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "ecr:BatchGetImage"
            }
        })

        assert len(results) == 1
        assert results[0].third_party_account_ids == {"999999999999"}
        assert results[0].actions_by_account["999999999999"] == ["ecr:BatchGetImage"]

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
                "Action": "ecr:BatchGetImage"
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
                "Action": "ecr:BatchGetImage"
            }
        })

        assert results == []
