"""
Tests for headroom.checks.base module.

Covers the summary fields BaseCheck.execute writes for every check,
independently of any one check's own fields.
"""

import time
from datetime import datetime
from typing import Iterator, List, cast
from unittest.mock import MagicMock, patch

import pytest
from boto3.session import Session

from headroom.checks.base import BaseCheck, CategorizedCheckResult
from headroom.enums import CheckCategory
from headroom.types import JsonDict


class StubCheck(BaseCheck[str]):
    """
    A check that makes no AWS calls, to exercise the base class alone.

    Writes the base document shape, as all nine SCP checks and one RCP
    check do.
    """

    CHECK_TYPE = "scps"

    def analyze(self, session: Session) -> List[str]:
        """Return one compliant resource without touching AWS."""
        return ["ami-11111111111111111"]

    def categorize_result(self, result: str) -> tuple[CheckCategory, JsonDict]:
        """Report every resource as compliant."""
        return CheckCategory.COMPLIANT, {"image_id": result}

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """Contribute only the violation count every check writes."""
        return {"violations": len(check_result.violations)}


class TwoListStubCheck(StubCheck):
    """
    A check that names its keys for what it scanned.

    Stands in for the six RCP checks that override `_build_results_data`,
    which receive a summary the base class has already built.
    """

    CHECK_TYPE = "rcps"

    def _build_results_data(self, check_result: CategorizedCheckResult) -> JsonDict:
        """Write the two-list shape in place of the base one."""
        return {
            "summary": check_result.summary,
            "keys_third_parties_can_access": [],
            "keys_with_wildcards": [],
        }


@pytest.fixture
def pacific_timezone(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """
    Run the test as though the scanning machine sits in US Pacific time.

    `scanned_at` renders in the local zone of whatever machine ran the scan,
    so the expected string is fixed only once that zone is.
    """
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def write_results_for(check: StubCheck) -> JsonDict:
    """
    Run a check against a stub session and return what it would have written.

    Args:
        check: The check to execute

    Returns:
        The results_data dictionary handed to the writer
    """
    with (
        patch("headroom.checks.base.datetime") as mock_datetime,
        patch("headroom.checks.base.write_check_results") as mock_write,
    ):
        mock_datetime.now.return_value = datetime(2026, 9, 4, 16, 15)
        check.execute(MagicMock())
    results_data: JsonDict = mock_write.call_args[1]["results_data"]
    return results_data


class TestScannedAt:
    """The scan time every check records in its summary."""

    def test_execute_writes_the_scan_time_in_the_documented_format(
        self,
        pacific_timezone: None,
    ) -> None:
        """
        `summary.scanned_at` reads as the operator's wall clock.

        The expected string is written out rather than formatted, so the
        test and the code cannot agree by construction.
        """
        check = StubCheck(
            check_name="deny_ec2_ami_owner",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        summary = write_results_for(check)["summary"]

        assert summary == {
            "account_name": "security-tooling",
            "account_id": "111111111111",
            "check": "deny_ec2_ami_owner",
            "scanned_at": "09-04-2026 4:15 PM PDT",
            "violations": 0,
        }

    def test_the_two_list_shape_carries_the_scan_time_too(
        self,
        pacific_timezone: None,
    ) -> None:
        """
        Overriding `_build_results_data` does not drop the scan time.

        The six RCP checks that override it are handed a summary the base
        class built, so none of them has to remember the key.
        """
        check = TwoListStubCheck(
            check_name="deny_kms_third_party_access",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        summary = cast(JsonDict, write_results_for(check)["summary"])

        assert summary["scanned_at"] == "09-04-2026 4:15 PM PDT"


class OrderedStubCheck(StubCheck):
    """
    A check whose analysis results arrive in an order the test chooses.

    Each entry carries two fields so that ordering by the first is
    distinguishable from ordering by the second.
    """

    def __init__(
        self,
        entries: List[str],
        *,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
    ) -> None:
        """
        Hold the raw results `analyze` will return.

        Args:
            entries: Raw results, each `region|image_id`
            check_name: Name of the check
            account_name: Account name
            account_id: Account ID
            results_dir: Base directory for results
        """
        super().__init__(check_name, account_name, account_id, results_dir)
        self.entries = entries

    def analyze(self, session: Session) -> List[str]:
        """Return the raw results the test supplied, untouched."""
        return self.entries

    def categorize_result(self, result: str) -> tuple[CheckCategory, JsonDict]:
        """Report every resource as compliant, naming the image first."""
        region, image_id = result.split("|")
        return CheckCategory.COMPLIANT, {"image_id": image_id, "region": region}


class NullableFieldStubCheck(OrderedStubCheck):
    """
    A check whose second field is `None` on the findings that lack it.

    Stands in for an RCP check that resolves a principal only on the
    findings it could read one from. Both entries name the same region, so
    the first field ties and the sort has to compare the second.
    """

    def categorize_result(self, result: str) -> tuple[CheckCategory, JsonDict]:
        """Report every resource as compliant, `-` naming a principal nothing resolved."""
        return CheckCategory.COMPLIANT, {
            "region": "us-east-1",
            "service_principal": None if result == "-" else result,
        }


class VaryingFieldStubCheck(OrderedStubCheck):
    """
    A check that omits a field on the findings that have nothing to put in it.

    Its raw results keep `OrderedStubCheck`'s `region|image_id` shape, and
    an empty region is one the scan could not read, so that entry is written
    a field shorter than its neighbour.
    """

    def categorize_result(self, result: str) -> tuple[CheckCategory, JsonDict]:
        """Report every resource as compliant, naming its region only when there is one."""
        region, image_id = result.split("|")
        entry: JsonDict = {"image_id": image_id}
        if region:
            entry["region"] = region
        return CheckCategory.COMPLIANT, entry


class SetFieldStubCheck(OrderedStubCheck):
    """
    A check that puts a `set` in an entry, which no check may do.

    A set has no JSON form, and its iteration order differs between
    processes under hash randomization, so a sort key or a file derived
    from its `repr` would differ between two runs over the same resources.
    """

    def categorize_result(self, result: str) -> tuple[CheckCategory, JsonDict]:
        """Report every resource as compliant, with its regions as a set."""
        region, image_id = result.split("|")
        return CheckCategory.COMPLIANT, {"image_id": image_id, "regions": {region}}


class TestEvidenceOrdering:
    """The order `execute` writes violations, exemptions, and compliant in."""

    def test_entries_order_by_their_fields_in_authored_order(self) -> None:
        """
        `image_id` is written first, so it orders the list and `region` breaks ties.

        The two orders disagree: by `image_id` the us-west-2 entry leads, and
        by `region` the us-east-1 entry would. The expected list is written
        out rather than sorted, so the test cannot agree with the code by
        construction.
        """
        check = OrderedStubCheck(
            [
                "us-east-1|ami-22222222222222222",
                "us-west-2|ami-11111111111111111",
            ],
            check_name="deny_ec2_ami_owner",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        compliant = write_results_for(check)["compliant_instances"]

        assert compliant == [
            {"image_id": "ami-11111111111111111", "region": "us-west-2"},
            {"image_id": "ami-22222222222222222", "region": "us-east-1"},
        ]

    def test_arrival_order_does_not_change_the_written_file(self) -> None:
        """
        Two runs over the same resources write the same document.

        This is the property the whole rule exists for, stated without
        naming an order: what AWS returned first must not reach the file.
        The literal above pins which order; this pins that there is one.
        """
        entries = [
            "us-east-1|ami-22222222222222222",
            "us-west-2|ami-11111111111111111",
            "eu-west-1|ami-33333333333333333",
        ]
        arguments = {
            "check_name": "deny_ec2_ami_owner",
            "account_name": "security-tooling",
            "account_id": "111111111111",
            "results_dir": "/unused",
        }

        first = write_results_for(OrderedStubCheck(entries, **arguments))
        second = write_results_for(OrderedStubCheck(list(reversed(entries)), **arguments))

        assert first == second

    def test_a_field_holding_a_set_raises_rather_than_sorting_by_its_repr(self) -> None:
        """
        A value JSON cannot serialize fails the scan instead of ordering by its `repr`.

        `entry_sort_key` serializes each field to compare it, and passes no
        `default`: a set's `repr` lists its members in hash order, which
        changes between processes, so a key built from it would put the same
        two entries in a different order on the next run. Raising here is
        what keeps the "two runs write the same bytes" property provable.
        """
        check = SetFieldStubCheck(
            [
                "us-east-1|ami-22222222222222222",
                "us-west-2|ami-11111111111111111",
            ],
            check_name="deny_ec2_ami_owner",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        with pytest.raises(TypeError, match="not JSON serializable"):
            write_results_for(check)

    def test_a_field_that_is_none_on_one_entry_still_sorts(self) -> None:
        """
        A `None` beside a `str` at the same position has an order, not a TypeError.

        Both entries name us-east-1, so the tie carries the sort into the
        second field, where one entry holds a principal and the other holds
        nothing. Comparing the two values directly is what raises mid-scan;
        comparing them serialized puts the quoted string ahead of `null`.
        The expected list is written out rather than sorted.
        """
        check = NullableFieldStubCheck(
            ["-", "config.amazonaws.com"],
            check_name="deny_service_confused_deputy",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        compliant = write_results_for(check)["compliant_instances"]

        assert compliant == [
            {"region": "us-east-1", "service_principal": "config.amazonaws.com"},
            {"region": "us-east-1", "service_principal": None},
        ]

    def test_entries_of_different_lengths_order_by_the_fields_they_share(self) -> None:
        """
        A shorter entry that the longer one extends comes first.

        Both name the same image, so the shared field ties and the shorter
        entry runs out of fields to compare. Length decides, and it decides
        the same way whatever the missing field would have held. The
        expected list is written out rather than sorted.
        """
        check = VaryingFieldStubCheck(
            [
                "us-east-1|ami-11111111111111111",
                "|ami-11111111111111111",
            ],
            check_name="deny_ec2_ami_owner",
            account_name="security-tooling",
            account_id="111111111111",
            results_dir="/unused",
        )

        compliant = write_results_for(check)["compliant_instances"]

        assert compliant == [
            {"image_id": "ami-11111111111111111"},
            {"image_id": "ami-11111111111111111", "region": "us-east-1"},
        ]
