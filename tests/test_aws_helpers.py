"""
Tests for headroom.aws.helpers module.
"""

from typing import Any, Dict, Iterator, List
from unittest.mock import MagicMock

import pytest

from headroom.aws.helpers import find_tag_value_as_iam_matches, get_all_regions, paginate


class TestGetAllRegions:
    """Test region discovery."""

    def test_only_enabled_regions_are_requested(self) -> None:
        """
        describe_regions is called with no arguments, so AWS returns only the
        regions that are enabled for the account.

        This is the sole reason Headroom never calls a service API in a disabled
        region. Per the EC2 API, AllRegions "indicates whether to display all
        Regions, including Regions that are disabled for your account". Passing it
        would add not-opted-in regions to this list, and because every caller
        builds a per-region client from the result, each such region would produce
        a doomed API call against a region the account cannot use.

        Asserting the exact call signature rather than just the return value is
        deliberate: it fails the moment anyone adds AllRegions=True.
        """
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "eu-south-1", "OptInStatus": "opted-in"},
            ]
        }

        regions = get_all_regions(mock_session)

        mock_ec2.describe_regions.assert_called_once_with()
        assert regions == ["us-east-1", "eu-south-1"]

    def test_region_names_are_returned_in_response_order(self) -> None:
        """Region names are extracted verbatim, preserving the API's order."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "eu-west-1"},
                {"RegionName": "us-west-2"},
                {"RegionName": "us-east-1"},
            ]
        }

        assert get_all_regions(mock_session) == ["eu-west-1", "us-west-2", "us-east-1"]

    def test_no_regions_returns_empty_list(self) -> None:
        """An empty Regions list yields no regions rather than raising."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": []}

        assert get_all_regions(mock_session) == []


class TestPaginate:
    """Test the pagination wrapper."""

    def test_yields_every_page(self) -> None:
        """Each page from the paginator is yielded in order."""
        mock_client = MagicMock()
        paginator = MagicMock()
        pages: List[Dict[str, Any]] = [{"Items": [1]}, {"Items": [2]}]
        paginator.paginate.return_value = pages
        mock_client.get_paginator.return_value = paginator

        result = list(paginate(mock_client, "list_things"))

        mock_client.get_paginator.assert_called_once_with("list_things")
        assert result == pages

    def test_passes_operation_kwargs_through(self) -> None:
        """Operation keyword arguments reach the paginator unchanged."""
        mock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = []
        mock_client.get_paginator.return_value = paginator

        pages: Iterator[Dict[str, Any]] = paginate(
            mock_client, "list_things", MaxResults=50, Prefix="a"
        )
        assert list(pages) == []

        paginator.paginate.assert_called_once_with(MaxResults=50, Prefix="a")


class TestFindTagValueAsIamMatches:
    """
    One rule for reading a tag an `aws:RequestTag` condition names.

    Both tag checks call this. They used to read the same kind of tag by two
    different rules - `deny_ec2_imds_v1` case-insensitively on the key,
    `deny_eks_create_cluster_without_tag` exactly - and only one of them could
    be right. The tests here pin the rule itself; each check's own tests pin
    what it does with the answer.
    """

    def test_the_exact_key_returns_its_value(self) -> None:
        assert find_tag_value_as_iam_matches(
            {"PavedRoad": "true"}, "PavedRoad", "Cluster prod"
        ) == "true"

    @pytest.mark.parametrize("key", ["pavedroad", "PAVEDROAD", "pAvEdRoAd"])
    def test_the_key_matches_without_regard_to_case(self, key: str) -> None:
        """AWS matches a condition key name irrespective of its case."""
        assert find_tag_value_as_iam_matches(
            {key: "true"}, "PavedRoad", "Cluster prod"
        ) == "true"

    def test_the_value_is_returned_verbatim(self) -> None:
        """
        The caller compares the value, and must compare it exactly.

        Normalizing it here would hide the case-sensitive half of the match
        from every caller at once.
        """
        assert find_tag_value_as_iam_matches(
            {"PavedRoad": "TRUE"}, "PavedRoad", "Cluster prod"
        ) == "TRUE"

    def test_an_absent_key_is_none_rather_than_empty(self) -> None:
        """
        None distinguishes "no such tag" from a tag whose value is "".

        A caller comparing against "true" treats both as a violation, but the
        two are different facts and the helper does not merge them.
        """
        assert find_tag_value_as_iam_matches(
            {"Name": "prod"}, "PavedRoad", "Cluster prod"
        ) is None

    def test_an_empty_value_is_returned_as_itself(self) -> None:
        assert find_tag_value_as_iam_matches(
            {"PavedRoad": ""}, "PavedRoad", "Cluster prod"
        ) == ""

    def test_the_key_twice_in_differing_cases_raises(self) -> None:
        """
        Both spellings match the condition key; at most one value can.

        Returning either would invent a verdict for a live workload, so there
        is no answer to give.
        """
        with pytest.raises(RuntimeError, match=r"more than once in cases that differ"):
            find_tag_value_as_iam_matches(
                {"PavedRoad": "true", "pavedroad": "false"}, "PavedRoad", "Cluster prod"
            )

    def test_the_error_names_the_resource_and_every_spelling(self) -> None:
        """The operator has to find the tags, so the message carries them."""
        with pytest.raises(RuntimeError) as exc_info:
            find_tag_value_as_iam_matches(
                {"PavedRoad": "true", "pavedroad": "false"}, "PavedRoad", "Cluster prod"
            )

        assert "Cluster prod" in str(exc_info.value)
        assert "PavedRoad, pavedroad" in str(exc_info.value)
