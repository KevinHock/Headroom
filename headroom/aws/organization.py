"""
AWS Organizations analysis module.

This module contains functions for analyzing AWS Organizations structure
using the AWS Organizations API.
"""

import logging
from typing import Dict, List, Optional, Tuple

from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError
from mypy_boto3_organizations.client import OrganizationsClient
from mypy_boto3_organizations.type_defs import AccountTypeDef, OrganizationalUnitTypeDef

from ..types import OrganizationHierarchy, OrganizationalUnit, AccountOrgPlacement
from ..utils import make_safe_variable_name
from .helpers import paginate

# Set up logging
logger = logging.getLogger(__name__)


def _list_organizational_units(
    org_client: OrganizationsClient,
    parent_id: str
) -> List[OrganizationalUnitTypeDef]:
    """
    List every OU directly under a parent.

    Paginated: ListOrganizationalUnitsForParent caps a page at twenty, and AWS
    documents that it can return fewer even when more remain. Reading a single
    response would drop whole subtrees from the hierarchy without any error.

    Args:
        org_client: AWS Organizations client
        parent_id: Root or OU whose child OUs to list

    Returns:
        One entry per child OU
    """
    organizational_units: List[OrganizationalUnitTypeDef] = []
    for page in paginate(org_client, "list_organizational_units_for_parent", ParentId=parent_id):
        organizational_units.extend(page["OrganizationalUnits"])

    return organizational_units


def _list_accounts(
    org_client: OrganizationsClient,
    parent_id: str
) -> List[AccountTypeDef]:
    """
    List every account directly under a parent.

    Paginated for the same reason as `_list_organizational_units`. An account
    missing from the hierarchy is invisible to the OU-level RCP safety check in
    `headroom/terraform/generate_rcps.py`, which reads the hierarchy rather
    than the result files, so a truncated page there attaches a policy over an
    account that blocks it (INV-01).

    Args:
        org_client: AWS Organizations client
        parent_id: Root or OU whose accounts to list

    Returns:
        One entry per account
    """
    accounts: List[AccountTypeDef] = []
    for page in paginate(org_client, "list_accounts_for_parent", ParentId=parent_id):
        accounts.extend(page["Accounts"])

    return accounts


def _build_ou_hierarchy(
    org_client: OrganizationsClient,
    root_id: str,
    organizational_units: Dict[str, OrganizationalUnit],
    accounts: Dict[str, AccountOrgPlacement],
    parent_ou_id: Optional[str] = None,
    ou_path: Optional[List[str]] = None
) -> List[str]:
    """
    Recursively build OU hierarchy starting from parent_ou_id.

    Args:
        org_client: AWS Organizations client
        root_id: Organization root ID
        organizational_units: Dictionary to store OU information
        accounts: Dictionary to store account information
        parent_ou_id: Parent OU ID to start from
        ou_path: Current OU path from root

    Returns:
        The IDs of the OUs directly under this parent. The caller records them
        as that parent's children rather than listing them a second time.
    """
    if ou_path is None:
        ou_path = []

    try:
        child_ous = _list_organizational_units(org_client, parent_ou_id or root_id)
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"Failed to list OUs for parent {parent_ou_id}: {e}")

    for ou in child_ous:
        ou_id = ou["Id"]
        ou_name = ou["Name"]
        current_path = ou_path + [ou_name]

        grandchild_ou_ids = _build_ou_hierarchy(
            org_client, root_id, organizational_units, accounts, ou_id, current_path
        )

        try:
            ou_accounts = _list_accounts(org_client, ou_id)
        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(f"Failed to get accounts for OU {ou_id}: {e}")

        for acc in ou_accounts:
            accounts[acc["Id"]] = AccountOrgPlacement(
                account_id=acc["Id"],
                account_name=acc["Name"],
                parent_ou_id=ou_id,
                ou_path=current_path
            )

        organizational_units[ou_id] = OrganizationalUnit(
            ou_id=ou_id,
            name=ou_name,
            parent_ou_id=parent_ou_id,
            child_ous=grandchild_ou_ids,
            accounts=[acc["Id"] for acc in ou_accounts]
        )

    return [ou["Id"] for ou in child_ous]


def analyze_organization_structure(session: Session) -> OrganizationHierarchy:
    """
    Analyze AWS Organizations structure including root, OUs, and account relationships.

    Returns comprehensive hierarchy mapping.
    """
    org_client: OrganizationsClient = session.client("organizations")

    # Get root information. Not paginated: an organization has exactly one root.
    try:
        roots_response = org_client.list_roots()
        if not roots_response.get("Roots"):
            raise RuntimeError("No roots found in organization")
        root_id = roots_response["Roots"][0]["Id"]
        logger.info(f"Found organization root: {root_id}")
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"Failed to get organization root: {e}")

    # Build OU hierarchy recursively
    organizational_units: Dict[str, OrganizationalUnit] = {}
    accounts: Dict[str, AccountOrgPlacement] = {}

    # Build hierarchy starting from root
    _build_ou_hierarchy(org_client, root_id, organizational_units, accounts)

    # Get accounts directly under root
    try:
        root_accounts = _list_accounts(org_client, root_id)
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"Failed to get accounts under root: {e}")

    for acc in root_accounts:
        # No parent OU: these accounts hang directly off the organization root
        accounts[acc["Id"]] = AccountOrgPlacement(
            account_id=acc["Id"],
            account_name=acc["Name"],
            parent_ou_id=None,
            ou_path=["Root"]
        )

    return OrganizationHierarchy(
        root_id=root_id,
        organizational_units=organizational_units,
        accounts=accounts
    )


def create_account_ou_mapping(session: Session) -> Dict[str, Optional[str]]:
    """
    Create mapping of account IDs to their direct parent OU IDs.

    Returns dictionary with account_id -> parent_ou_id relationships.

    parent_ou_id is None for accounts attached directly to the organization root.
    """
    hierarchy = analyze_organization_structure(session)
    mapping: Dict[str, Optional[str]] = {}

    for account_id, account_info in hierarchy.accounts.items():
        mapping[account_id] = account_info.parent_ou_id

    return mapping


def _format_account_candidates(candidates: List[Tuple[str, str]]) -> str:
    """
    Render account candidates as a readable list for error messages.

    Args:
        candidates: List of (account_id, account_name) pairs

    Returns:
        Comma-separated string, e.g. "111111111111 ('Prod'), 222222222222 ('prod')"
    """
    return ", ".join(f"{acc_id} ('{name}')" for acc_id, name in sorted(candidates))


def lookup_account_id_by_name(
    account_name: str,
    organization_hierarchy: OrganizationHierarchy,
    context: str = "result file"
) -> str:
    """
    Look up account ID by name in organization hierarchy.

    Matches the name exactly first. Result files are written under the name
    configured by use_account_name_from_tags, which can be a slug such as
    "management-account" where Organizations reports "Management Account", so a
    name that matches nothing exactly falls back to comparing names with case
    and separators ignored. The fallback resolves only when exactly one account
    matches; anything else aborts rather than attribute results to a guess.

    Args:
        account_name: Account name to look up
        organization_hierarchy: Organization structure containing accounts
        context: Context string for error message (e.g., "result file", "check processing")

    Returns:
        Account ID of the single account matching the account name

    Raises:
        RuntimeError: If the account name matches no account, or matches more
            than one (Organizations enforces uniqueness on account email, not
            on account name)
    """
    exact_matches = [
        (acc_id, acc_info.account_name)
        for acc_id, acc_info in organization_hierarchy.accounts.items()
        if acc_info.account_name == account_name
    ]

    if len(exact_matches) == 1:
        acc_id = exact_matches[0][0]
        logger.info(f"Looked up account_id {acc_id} for account name '{account_name}'")
        return acc_id

    if exact_matches:
        raise RuntimeError(
            f"Account name '{account_name}' from {context} matches multiple accounts "
            f"in the organization hierarchy: {_format_account_candidates(exact_matches)}"
        )

    # A name of only separators canonicalizes to "", which would otherwise
    # match every other such name, so it is left unresolved.
    canonical_name = make_safe_variable_name(account_name)
    canonical_matches: List[Tuple[str, str]] = []
    if canonical_name:
        canonical_matches = [
            (acc_id, acc_info.account_name)
            for acc_id, acc_info in organization_hierarchy.accounts.items()
            if make_safe_variable_name(acc_info.account_name) == canonical_name
        ]

    if len(canonical_matches) == 1:
        acc_id, matched_name = canonical_matches[0]
        logger.warning(
            f"Account name '{account_name}' from {context} does not match any "
            f"account name in the organization hierarchy exactly; resolved to "
            f"account_id {acc_id} ('{matched_name}') by ignoring case and separators"
        )
        return acc_id

    if canonical_matches:
        raise RuntimeError(
            f"Account name '{account_name}' from {context} matches multiple accounts "
            f"in the organization hierarchy when ignoring case and separators: "
            f"{_format_account_candidates(canonical_matches)}"
        )

    raise RuntimeError(
        f"Account name '{account_name}' from {context} not found in organization hierarchy"
    )
