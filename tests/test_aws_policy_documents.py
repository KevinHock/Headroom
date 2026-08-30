"""
Tests for headroom.aws.policy_documents module.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List

import pytest

import headroom

from headroom.aws.policy_documents import (
    MalformedPolicyError,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    TRUST_POLICY_PRINCIPAL_TYPES,
    UnknownPrincipalTypeError,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_actions,
    normalize_statements,
    read_principal,
    read_service_principal_sources,
    unreadable_service_principal_source,
)
from headroom.types import JsonDict
from tests.constants import ORG_ID


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


class TestNormalizeActions:
    def test_an_action_that_is_neither_string_nor_list_raises(self) -> None:
        """
        A malformed Action is a document AWS could not have stored.

        IAM accepts a string or an array of strings and nothing else, so
        anything else means Headroom has misread the document. Two analyzers
        used to answer an empty set, recording the resource as granting no
        action at all, which is the fallback CONVENTIONS.md forbids and a
        verdict nobody measured.
        """
        with pytest.raises(TypeError) as exc_info:
            normalize_actions(None)  # type: ignore[arg-type]

        assert "NoneType" in str(exc_info.value)

    def test_a_string_is_one_action(self) -> None:
        """A lone action is stored as a bare string."""
        assert normalize_actions("s3:GetObject") == {"s3:GetObject"}

    def test_a_list_is_every_action_it_names(self) -> None:
        """An array grants each action in it."""
        assert normalize_actions(["sqs:SendMessage", "sqs:ReceiveMessage"]) == {
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
        }

    def test_an_empty_list_is_no_actions(self) -> None:
        """
        A statement with no Action key reaches this as the empty default.

        Every caller passes `statement.get("Action", [])`, so this is the
        ordinary path for a statement that names none, not a malformed one.
        """
        assert normalize_actions([]) == set()

    def test_a_dict_raises_rather_than_reading_its_keys(self) -> None:
        """
        An object Action must not be read as the set of its keys.

        `set({"unexpected": "shape"})` is `{"unexpected"}`, so two analyzers
        used to record a key name as though it were an IAM action.
        """
        with pytest.raises(TypeError, match="Expected str or list"):
            normalize_actions({"unexpected": "shape"})  # type: ignore[arg-type]


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


class TestServicePrincipalSources:
    """Test read_service_principal_sources against every disposition."""
    ORG_ACCOUNTS = {"111111111111"}
    WHERE = "Bucket 'a-bucket'"

    @staticmethod
    def _statement(principal: Any, condition: Any = None) -> Dict[str, Any]:
        """Build one Allow statement, optionally with a Condition block."""
        statement: Dict[str, Any] = {
            "Effect": "Allow",
            "Principal": principal,
            "Action": "s3:PutObject",
        }
        if condition is not None:
            statement["Condition"] = condition
        return statement

    def test_no_service_principal_reports_nothing(self) -> None:
        """A statement naming only AWS principals has no service source."""
        statement = self._statement({"AWS": "arn:aws:iam::999999999999:root"})

        assert read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        ) == []

    def test_unguarded_service_principal_is_recorded_not_allowlisted(self) -> None:
        """
        A Service principal with no source key names no account to permit.

        The policy pins nothing, so there is nothing for the allowlist to
        carry. The trust is still within the statement's reach - the
        calling service populates aws:SourceAccount itself - which is why
        the rollout guidance sends the operator to CloudTrail for the
        drivers this read cannot see.
        """
        statement = self._statement({"Service": "sns.amazonaws.com"})

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert len(sources) == 1
        assert sources[0].service_principal == "sns.amazonaws.com"
        assert sources[0].source_account_ids == []
        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_in_org_source_account_is_not_allowlisted(self) -> None:
        """A source already inside the organization needs no allowlist entry."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "111111111111"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == []
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_out_of_org_source_account_reaches_the_allowlist(self) -> None:
        """A third-party source is what the allowlist exists to carry."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_wildcard_source is False

    def test_condition_keys_are_matched_case_insensitively(self) -> None:
        """IAM matches condition key names without regard to case."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:sourceaccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]

    def test_source_arn_yields_its_account(self) -> None:
        """aws:SourceArn is the more common pin, and carries the account."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"ArnLike": {
                "aws:SourceArn": "arn:aws:sns:us-west-2:999999999999:a-topic"
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_wildcard_source is False

    def test_wildcard_source_account_cannot_be_expressed(self) -> None:
        """An unbounded source set is what withholds the statement."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceAccount": "*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True
        assert sources[0].source_account_ids == []

    def test_wildcard_account_in_source_arn_cannot_be_expressed(self) -> None:
        """An ARN whose account field is a wildcard names no account."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-west-2:*:a-topic"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bucket_arn_alone_cannot_be_expressed(self) -> None:
        """
        S3 ARNs carry no account field at all.

        `arn:aws:s3:::a-bucket` never identifies whose bucket drove the
        call, which is why AWS pairs aws:SourceArn with aws:SourceAccount.
        """
        statement = self._statement(
            {"Service": "s3.amazonaws.com"},
            {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::a-bucket"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bucket_arn_resolves_through_its_companion_source_account(self) -> None:
        """The companion key is what makes an accountless ARN readable."""
        statement = self._statement(
            {"Service": "s3.amazonaws.com"},
            {
                "ArnLike": {"aws:SourceArn": "arn:aws:s3:::a-bucket"},
                "StringEquals": {"aws:SourceAccount": "999999999999"},
            },
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].source_account_ids == ["999999999999"]
        assert sources[0].has_wildcard_source is False

    def test_every_service_principal_in_one_statement_is_reported(self) -> None:
        """One Condition block guards every service the statement names."""
        statement = self._statement(
            {"Service": ["sns.amazonaws.com", "events.amazonaws.com"]},
            {"StringEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert [source.service_principal for source in sources] == [
            "sns.amazonaws.com",
            "events.amazonaws.com",
        ]
        assert all(s.source_account_ids == ["999999999999"] for s in sources)

    def test_aws_and_service_principals_together_report_only_the_service(self) -> None:
        """The AWS principal path is untouched by this reader."""
        statement = self._statement(
            {
                "AWS": "arn:aws:iam::999999999999:root",
                "Service": "sns.amazonaws.com",
            }
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert len(sources) == 1
        assert sources[0].service_principal == "sns.amazonaws.com"

    def test_source_org_id_naming_this_organization_needs_no_allowlist(self) -> None:
        """
        A guard pinned to our own organization is a perfect guard.

        The deployed statement exempts a source carrying this
        organization's ID, so the resource needs no allowlist entry and is
        not a violation. This is AWS's own recommended service principal
        guard, and treating it as unreadable withheld the statement from
        every other resource in the account.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceOrgID": ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].source_account_ids == []
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_source_org_id_naming_another_organization_is_unenumerable(self) -> None:
        """
        A foreign organization names accounts no allowlist can carry.

        The allowlist holds account IDs, and the accounts of another
        organization are not knowable from here, so the statement is
        withheld rather than deployed against an allowlist that cannot
        cover them.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceOrgID": "o-notours98765"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is True

    def test_wildcarded_source_org_id_is_not_read_as_this_organization(self) -> None:
        """
        A trailing wildcard on our own ID also matches other organizations.

        `o-example12345*` matches this organization and every organization
        whose ID extends that prefix, so reading it as ours would deploy
        the statement against sources it does not cover.
        """
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgID": f"{ORG_ID}*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_source_org_paths_inside_this_organization_needs_no_allowlist(self) -> None:
        """An organization path carries the organization ID as its first element."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {
                "aws:SourceOrgPaths": f"{ORG_ID}/r-ab12/ou-ab12-11111111/"
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None
        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_source_org_paths_below_this_organization_needs_no_allowlist(self) -> None:
        """A wildcard below our own organization stays inside it."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": f"{ORG_ID}/*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is False

    def test_source_org_paths_in_another_organization_is_unenumerable(self) -> None:
        """A path rooted in a foreign organization is no more enumerable than its ID."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": "o-notours98765/*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_bare_wildcard_source_org_paths_is_unenumerable(self) -> None:
        """A path of `*` matches every organization, so it names no organization."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringLike": {"aws:SourceOrgPaths": "*"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_one_foreign_organization_scope_among_several_is_enough(self) -> None:
        """Any scope the allowlist cannot cover withholds the statement."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {
                "aws:SourceOrgID": [ORG_ID, "o-notours98765"]
            }},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_wildcard_source is True

    def test_organization_scope_key_case_is_ignored(self) -> None:
        """IAM matches condition key names without regard to case."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:sourceorgid": ORG_ID}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is True
        assert sources[0].has_wildcard_source is False

    def test_negated_operator_on_an_organization_scope_is_recorded(self) -> None:
        """The operator gate covers the organization keys too."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringNotEquals": {"aws:SourceOrgID": "o-notours98765"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "StringNotEquals" in sources[0].read_failure

    def test_negated_operator_on_a_source_key_is_recorded(self) -> None:
        """A negated operator excludes rather than permits; it is no guard."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringNotEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "StringNotEquals" in sources[0].read_failure

    def test_malformed_source_account_is_recorded(self) -> None:
        """A source account that is neither an ID nor a wildcard is unreadable."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "not-an-account"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "not-an-account" in sources[0].read_failure

    def test_non_string_source_condition_value_is_recorded(self) -> None:
        """A source key holding neither a string nor a list is unreadable."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": 123}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is not None
        assert "int" in sources[0].read_failure

    def test_a_readable_statement_records_no_failure(self) -> None:
        """The failure field stays None on every guard the parser can read."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": "999999999999"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].read_failure is None

    def test_unrelated_conditions_are_ignored(self) -> None:
        """Only the four source keys are read; everything else passes by."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"StringEquals": {"aws:SecureTransport": "true"}},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_operator_with_non_mapping_entries_is_ignored(self) -> None:
        """An operator whose value is not itself a mapping guards nothing."""
        statement = self._statement(
            {"Service": "sns.amazonaws.com"},
            {"Bool": "true"},
        )

        sources = read_service_principal_sources(
            statement, self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        )

        assert sources[0].has_source_condition is False
        assert sources[0].has_wildcard_source is False

    def test_wildcard_principal_string_reports_nothing(self) -> None:
        """`Principal: "*"` is not a dict and names no service."""
        assert read_service_principal_sources(
            self._statement("*"), self.ORG_ACCOUNTS, ORG_ID, self.WHERE
        ) == []


class TestHasActionableServicePrincipalSource:
    """Test has_actionable_service_principal_source against every disposition."""

    @staticmethod
    def _source(
        source_account_ids: List[str], has_wildcard_source: bool
    ) -> ServicePrincipalSource:
        """Build one service principal source with the fields under test."""
        return ServicePrincipalSource(
            service_principal="sns.amazonaws.com",
            source_account_ids=source_account_ids,
            has_source_condition=True,
            has_wildcard_source=has_wildcard_source,
        )

    def test_a_failed_read_is_actionable(self) -> None:
        """
        A resource whose guard could not be read must reach the check.

        Dropping it would leave the confused deputy statement to deploy
        against an allowlist nobody could compute.
        """
        sources = [unreadable_service_principal_source("could not be read")]

        assert has_actionable_service_principal_source(sources) is True

    def test_an_unguarded_source_is_not_actionable(self) -> None:
        """An unguarded trust would bury the sources that matter."""
        sources = [
            ServicePrincipalSource(
                service_principal="sns.amazonaws.com",
                source_account_ids=[],
                has_source_condition=False,
                has_wildcard_source=False,
            )
        ]

        assert has_actionable_service_principal_source(sources) is False

    def test_an_out_of_org_account_id_is_actionable(self) -> None:
        """A source naming an out-of-organization account is worth keeping."""
        sources = [self._source(["999999999999"], False)]

        assert has_actionable_service_principal_source(sources) is True

    def test_a_wildcard_guard_is_actionable(self) -> None:
        """A guard no allowlist can express is worth keeping, even unresolved."""
        sources = [self._source([], True)]

        assert has_actionable_service_principal_source(sources) is True

    def test_no_sources_is_not_actionable(self) -> None:
        """A statement naming no service principal has nothing worth keeping."""
        assert has_actionable_service_principal_source([]) is False


class TestOneReaderPerStatementElement:
    """
    The readers of a statement element live in policy_documents.py alone.

    Six copies of the Principal walk once disagreed four ways, and five copies
    of the Action reader disagreed four ways after that. Both were collapsed
    into one function, but nothing stopped a seventh copy appearing next to a
    new feature - which is how every previous copy arrived. These pin the
    collapse statically, because a divergent copy fails no other test: each
    analyzer's own suite passes against its own reader, which is exactly how
    the drift survived.

    A statement element is polymorphic - a string, a list, or an object - so a
    function taking one is a reader. The exceptions below all take a plain
    `str` and are named here rather than excluded by a rule, so that adding one
    is a deliberate edit.
    """

    @staticmethod
    def _functions_taking(parameter_names: frozenset[str]) -> set[str]:
        """
        Report every function in the package taking one of these parameters.

        Args:
            parameter_names: The parameter names that mark a reader

        Returns:
            "<module>.<function>" for each, module-relative to the package
        """
        package_root = Path(headroom.__file__).parent

        found = set()
        for path in sorted(package_root.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.FunctionDef):
                    continue
                arguments = node.args.args + node.args.kwonlyargs
                if not parameter_names.intersection(a.arg for a in arguments):
                    continue
                module = path.relative_to(package_root).as_posix()
                found.add(f"{module}.{node.name}")

        return found

    def test_only_policy_documents_reads_a_statement_principal(self) -> None:
        """A Principal element is read in one place, or it drifts."""
        assert self._functions_taking(frozenset({"principal"})) == {
            "aws/policy_documents.py._account_ids_in_string",
            "aws/policy_documents.py.read_principal",
            "aws/policy_documents.py._service_principals",
            # A grant's principal is a plain ARN string from ListGrants, not a
            # statement's Principal element, and no allowlist reads it.
            "aws/kms.py._grant_principal_account_id",
            "aws/kms.py._external_grant_account",
        }

    def test_only_policy_documents_normalizes_a_statement_action(self) -> None:
        """An Action element is read in one place, or it drifts."""
        assert self._functions_taking(frozenset({"action", "actions"})) == {
            "aws/policy_documents.py.normalize_actions",
            # Matches one already-normalized action against one pattern; it
            # never sees the Action element.
            "aws/iam/roles.py._action_pattern_matches",
        }
