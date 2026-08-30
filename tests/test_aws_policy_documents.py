"""
Tests for headroom.aws.policy_documents module.
"""

import pytest

from headroom.aws.policy_documents import (
    MalformedPolicyError,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    TRUST_POLICY_PRINCIPAL_TYPES,
    UnknownPrincipalTypeError,
    has_not_principal,
    normalize_statements,
    read_principal,
)
from headroom.types import JsonDict


class TestNormalizeStatements:
    def test_list_of_statements_is_returned_unchanged(self) -> None:
        """A Statement list passes through as-is."""
        first = {"Effect": "Allow", "Principal": {"AWS": "999999999999"}}
        second = {"Effect": "Deny", "Principal": "*"}
        policy: JsonDict = {"Version": "2012-10-17", "Statement": [first, second]}

        assert normalize_statements(policy, "Bucket 'example'") == [first, second]

    def test_lone_statement_object_becomes_a_one_element_list(self) -> None:
        """
        IAM accepts a lone statement object, so it reads as one statement.

        Returning an empty list here would report the policy as granting
        nothing, and iterating the object directly yields its keys as
        strings, which crashes on the first `statement.get`.
        """
        statement = {"Effect": "Allow", "Principal": {"AWS": "999999999999"}}
        policy: JsonDict = {"Version": "2012-10-17", "Statement": statement}

        assert normalize_statements(policy, "Bucket 'example'") == [statement]

    def test_missing_statement_key_is_no_statements(self) -> None:
        """A document with no Statement key grants nothing."""
        policy: JsonDict = {"Version": "2012-10-17"}

        assert normalize_statements(policy, "Bucket 'example'") == []

    def test_statement_string_raises(self) -> None:
        """A string Statement is malformed, and guessing at it is unsafe."""
        policy: JsonDict = {"Version": "2012-10-17", "Statement": "Allow"}

        with pytest.raises(MalformedPolicyError) as exc_info:
            normalize_statements(policy, "Bucket 'example'")

        message = str(exc_info.value)
        assert "Bucket 'example'" in message
        assert "Statement of type str" in message

    def test_statement_null_raises(self) -> None:
        """A null Statement is malformed for the same reason."""
        policy: JsonDict = {"Version": "2012-10-17", "Statement": None}

        with pytest.raises(MalformedPolicyError, match="Statement of type NoneType"):
            normalize_statements(policy, "Key 'example-key' in us-east-1")


class TestHasNotPrincipal:
    def test_not_principal_is_reported(self) -> None:
        """A statement naming NotPrincipal reaches everyone it excludes."""
        statement = {
            "Effect": "Allow",
            "NotPrincipal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "s3:GetObject",
        }

        assert has_not_principal(statement) is True

    def test_ordinary_principal_is_not_reported(self) -> None:
        """A Principal names who it grants to, so the analyzer can read it."""
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "s3:GetObject",
        }

        assert has_not_principal(statement) is False

    def test_both_elements_is_reported(self) -> None:
        """
        Carrying both is invalid IAM, and the answer still errs toward blocking.

        Letting the Principal half stand alone would report a narrow grant
        for a statement whose reach is everyone outside the exclusion list.
        """
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "NotPrincipal": {"AWS": "arn:aws:iam::888888888888:root"},
            "Action": "s3:GetObject",
        }

        assert has_not_principal(statement) is True


class TestReadPrincipal:
    def test_an_account_id_is_read_as_itself(self) -> None:
        """The shortened account-ID form names the account directly."""
        reading = read_principal(
            {"AWS": "111111111111"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    def test_an_arn_yields_the_account_it_names(self) -> None:
        """The account segment of an ARN is the fifth colon-delimited field."""
        reading = read_principal(
            {"AWS": "arn:aws:iam::222222222222:role/example"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"222222222222"}

    def test_a_bare_wildcard_is_a_wildcard_naming_no_account(self) -> None:
        """`Principal: "*"` reaches everyone, so it names nobody in particular."""
        reading = read_principal(
            "*", RESOURCE_POLICY_PRINCIPAL_TYPES, "Queue 'example'"
        )

        assert reading.has_wildcard is True
        assert reading.account_ids == set()

    def test_a_service_principal_names_no_account(self) -> None:
        """A service principal is not an account and is not a blocker."""
        reading = read_principal(
            {"Service": "s3.amazonaws.com"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is False
        assert reading.has_non_account_principals is False

    def test_a_federated_principal_names_no_account(self) -> None:
        """
        A SAML provider ARN carries twelve digits that are not the caller's.

        They name the account hosting the provider. Reading them as the
        principal's account would put a stranger's identity into an
        allowlist keyed on aws:PrincipalAccount.
        """
        reading = read_principal(
            {"Federated": "arn:aws:iam::333333333333:saml-provider/Example"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.has_non_account_principals is True
        assert reading.account_ids == set()

    def test_a_canonical_user_names_no_account(self) -> None:
        """A canonical user ID is opaque; no allowlist can carry it."""
        reading = read_principal(
            {"CanonicalUser": "d" * 64},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Bucket 'example'",
        )

        assert reading.has_non_account_principals is True
        assert reading.account_ids == set()

    def test_a_canonical_user_is_not_permitted_in_a_trust_policy(self) -> None:
        """
        Only S3 accepts a canonical user, and a trust policy is not S3's.

        Reference:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
        """
        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            read_principal(
                {"CanonicalUser": "d" * 64},
                TRUST_POLICY_PRINCIPAL_TYPES,
                "Role 'example'",
            )

        assert "Role 'example'" in str(exc_info.value)

    def test_a_key_aws_does_not_document_raises(self) -> None:
        """A key outside the documented four is a document Headroom cannot read."""
        with pytest.raises(UnknownPrincipalTypeError) as exc_info:
            read_principal(
                {"Kerberos": "example"},
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'example'",
            )

        message = str(exc_info.value)
        assert "Kerberos" in message
        assert "Queue 'example'" in message

    def test_a_known_key_alongside_an_unknown_one_still_raises(self) -> None:
        """The readable half does not excuse the half nobody can read."""
        with pytest.raises(UnknownPrincipalTypeError):
            read_principal(
                {"AWS": "111111111111", "Kerberos": "example"},
                RESOURCE_POLICY_PRINCIPAL_TYPES,
                "Queue 'example'",
            )

    def test_a_list_of_accounts_yields_every_account(self) -> None:
        """An array of principals grants to each of them."""
        reading = read_principal(
            {"AWS": ["111111111111", "arn:aws:iam::222222222222:root"]},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111", "222222222222"}

    def test_a_wildcard_inside_a_list_is_a_wildcard(self) -> None:
        """One wildcard entry opens the grant however many accounts follow it."""
        reading = read_principal(
            {"AWS": ["111111111111", "*"]},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.has_wildcard is True
        assert reading.account_ids == {"111111111111"}

    def test_an_account_and_a_federated_principal_report_both(self) -> None:
        """One statement can name a readable account and an unreadable one."""
        reading = read_principal(
            {
                "AWS": "111111111111",
                "Federated": "arn:aws:iam::333333333333:saml-provider/Example",
            },
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"111111111111"}
        assert reading.has_non_account_principals is True

    def test_an_sts_session_arn_resolves_to_its_account(self) -> None:
        """The service segment is unconstrained, so sts ARNs resolve."""
        reading = read_principal(
            {"AWS": "arn:aws:sts::444444444444:assumed-role/Example/session"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == {"444444444444"}

    def test_an_unrecognizable_string_yields_no_account(self) -> None:
        """A principal that is neither an ARN nor an account ID names none."""
        reading = read_principal(
            {"AWS": "not-an-arn"},
            RESOURCE_POLICY_PRINCIPAL_TYPES,
            "Queue 'example'",
        )

        assert reading.account_ids == set()
        assert reading.has_wildcard is False


class TestPrincipalArnCoverage:
    """
    Every documented principal ARN form must yield its account ID.

    The analyzers once matched only `^arn:aws:iam::(\\d{12}):`, so STS session
    principals - which AWS documents as valid in a resource-based policy, and
    a role trust policy is one - and every non-commercial partition produced
    no account ID at all.
    """

    PARTNER = "999999999999"

    @pytest.mark.parametrize("principal", [
        "arn:aws:iam::999999999999:root",
        "arn:aws:iam::999999999999:role/vendor",
        "arn:aws:iam::999999999999:user/vendor",
        "arn:aws:sts::999999999999:assumed-role/vendor/session",
        "arn:aws:sts::999999999999:federated-user/vendor",
        "arn:aws-us-gov:iam::999999999999:role/vendor",
        "arn:aws-cn:iam::999999999999:role/vendor",
        "999999999999",
    ])
    def test_principal_yields_account_id(self, principal: str) -> None:
        """Each documented principal form resolves to its account."""
        reading = read_principal(
            principal, RESOURCE_POLICY_PRINCIPAL_TYPES, "Role 'example'"
        )

        assert reading.account_ids == {self.PARTNER}

    def test_non_account_principal_yields_nothing(self) -> None:
        """A service principal carries no account ID."""
        reading = read_principal(
            "ec2.amazonaws.com", RESOURCE_POLICY_PRINCIPAL_TYPES, "Role 'example'"
        )

        assert reading.account_ids == set()
