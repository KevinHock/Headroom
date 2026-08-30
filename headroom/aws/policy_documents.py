"""
Shared grammar for the IAM policy documents Headroom reads.

Resource policies and trust policies come back from every service in the
shape they were stored, so the analyzers all face the same variations. The
rules live here once rather than in each of them.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Set, Union

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN

__all__ = [
    "MalformedPolicyError",
    "NON_ACCOUNT_PRINCIPAL_TYPES",
    "PrincipalElement",
    "PrincipalReading",
    "RESOURCE_POLICY_PRINCIPAL_TYPES",
    "TRUST_POLICY_PRINCIPAL_TYPES",
    "UnknownPrincipalTypeError",
    "has_not_principal",
    "normalize_actions",
    "normalize_statements",
    "read_principal",
]

# The keys AWS documents for the Principal element, split by the policy type
# that accepts them. A canonical user ID is an Amazon S3 identifier and appears
# only in the policies of services that accept one; a role trust policy does
# not. Reference:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
RESOURCE_POLICY_PRINCIPAL_TYPES = frozenset({"AWS", "CanonicalUser", "Federated", "Service"})
TRUST_POLICY_PRINCIPAL_TYPES = frozenset({"AWS", "Federated", "Service"})

# The principal types that carry no account ID, so that no allowlist keyed on
# aws:PrincipalAccount can preserve their access. A SAML provider ARN does hold
# twelve digits, but they name the account hosting the provider rather than the
# caller, and a canonical user ID maps to an account only through an API call
# the scan does not make.
NON_ACCOUNT_PRINCIPAL_TYPES = frozenset({"CanonicalUser", "Federated"})

ACCOUNT_ID_PATTERN = r"^\d{12}$"

# A Principal element is a string, an array of them, or an object keyed by
# principal type whose values are again strings or arrays.
PrincipalElement = Union[str, List["PrincipalElement"], Dict[str, "PrincipalElement"]]


class MalformedPolicyError(Exception):
    """Raised when a policy document's Statement is neither an object nor a list."""


class UnknownPrincipalTypeError(Exception):
    """
    Raised when a Principal element names a key AWS does not document.

    Every analyzer lets this abort the run. AWS validates the Principal
    element when it stores a policy, so a key outside the documented set is
    a document Headroom has misread or a principal type AWS has added since
    this was written - not an ordinary fact about the account. Recording it
    as a finding would state a verdict on a grant nobody has modelled.
    """


@dataclass(frozen=True)
class PrincipalReading:
    """
    What one Principal element grants, as far as an RCP allowlist can express it.

    Attributes:
        account_ids: Every account ID the element names
        has_wildcard: True if it reaches principals the analyzer cannot
            enumerate, which is `*` under `Principal` or under `AWS`
        has_non_account_principals: True if it names a principal type that
            carries no account ID, so no allowlist can preserve its access
    """
    account_ids: Set[str]
    has_wildcard: bool
    has_non_account_principals: bool


def normalize_statements(policy: Mapping[str, Any], resource_description: str) -> List[Any]:
    """
    Return a policy document's statements as a list.

    IAM accepts a lone statement object where a one-element list would do,
    so both forms reach the analyzers. Iterating the object directly walks
    its keys as strings, which fails on the first `statement.get`.

    Read-only Mapping rather than dict because boto3 hands trust policies
    back as a TypedDict, which a dict parameter would reject.

    Args:
        policy: Parsed policy document
        resource_description: The resource this policy belongs to, named in
            the error message

    Returns:
        The document's statements, always as a list

    Raises:
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        return [statements]

    if not isinstance(statements, list):
        raise MalformedPolicyError(
            f"{resource_description} has a Statement of type "
            f"{type(statements).__name__}, expected an object or a list. "
            "Reading it as no statements would report the policy as granting "
            "nothing, which is not a safe guess."
        )

    return statements


def normalize_actions(action: Union[str, List[str]]) -> Set[str]:
    """
    Return a statement's Action element as a set of action strings.

    IAM accepts a string or an array of strings and nothing else, so anything
    else is a document AWS could not have stored - the same kind of trouble as
    a principal key AWS does not document, and answered the same way. Reading
    it as no actions would record the resource as granting nothing, which is a
    verdict on a grant nobody measured.

    Args:
        action: The statement's Action element

    Returns:
        Every action the element names

    Raises:
        TypeError: If the element is neither a string nor a list
    """
    if isinstance(action, str):
        return {action}

    if isinstance(action, list):
        return set(action)

    raise TypeError(
        f"Unexpected action type: {type(action).__name__}. Expected str or list."
    )


def has_not_principal(statement: Mapping[str, Any]) -> bool:
    """
    Report whether a statement names NotPrincipal in place of Principal.

    An Allow statement with NotPrincipal grants to every principal except
    the ones it names, so its reach is everyone outside a short list. That
    is what `has_wildcard_principal` already records for `Principal: "*"`,
    and reading NotPrincipal the same way is the accurate reading rather
    than a cautious one: the two forms grant the same access.

    Callers must apply this after their own Effect gate. Deny with
    NotPrincipal is the form AWS recommends, it restricts rather than
    grants, and a resource policy's Deny hands access to nobody.

    A statement carrying both elements is not valid IAM and cannot be
    stored, but were one to arrive, answering True keeps it on the blocking
    path rather than letting the Principal half stand in for a grant that
    is broader than it looks.

    Args:
        statement: One statement from a resource policy or trust policy

    Returns:
        True if the statement carries a NotPrincipal element
    """
    return "NotPrincipal" in statement


def _account_ids_in_string(principal: str) -> Set[str]:
    """
    Return the account ID a principal string names, if it names one.

    A wildcard, a service principal, and a canonical user ID all name none.

    Args:
        principal: One principal string from a Principal element

    Returns:
        The account ID as a one-element set, or an empty set
    """
    arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
    if arn_match:
        return {arn_match.group(1)}

    if re.match(ACCOUNT_ID_PATTERN, principal):
        return {principal}

    return set()


def read_principal(
    principal: PrincipalElement,
    permitted_types: FrozenSet[str],
    resource_description: str,
) -> PrincipalReading:
    """
    Read one Principal element into the three facts an RCP allowlist turns on.

    An allowlist keyed on `aws:PrincipalAccount` can preserve exactly one kind
    of grant: one naming accounts. This reports which accounts a principal
    names, and the two ways it can name something no allowlist can carry - a
    wildcard, and a principal type that has no account ID.

    The two are one verdict, not two mechanisms: both mean the RCP would deny
    a grant that exists today, so both must block the account. Which of them
    it was is reported, not acted on differently.

    An undocumented principal key is the separate case, and raises. See
    `UnknownPrincipalTypeError`.

    Args:
        principal: The Principal element's value, as a string, a list, or an
            object keyed by principal type
        permitted_types: The principal keys this policy type accepts, either
            `RESOURCE_POLICY_PRINCIPAL_TYPES` or `TRUST_POLICY_PRINCIPAL_TYPES`
        resource_description: The resource this policy belongs to, named in
            the error message

    Returns:
        What the element names

    Raises:
        UnknownPrincipalTypeError: If it names a key AWS does not document,
            or one this policy type does not accept
    """
    if isinstance(principal, str):
        return PrincipalReading(
            account_ids=_account_ids_in_string(principal),
            has_wildcard=principal == "*",
            has_non_account_principals=False,
        )

    if isinstance(principal, list):
        readings = [
            read_principal(item, permitted_types, resource_description)
            for item in principal
        ]
        account_ids: Set[str] = set()
        for reading in readings:
            account_ids.update(reading.account_ids)
        return PrincipalReading(
            account_ids=account_ids,
            has_wildcard=any(reading.has_wildcard for reading in readings),
            has_non_account_principals=any(
                reading.has_non_account_principals for reading in readings
            ),
        )

    unknown_types = set(principal.keys()) - permitted_types
    if unknown_types:
        raise UnknownPrincipalTypeError(
            f"{resource_description} names principal type(s) "
            f"{sorted(unknown_types)}, which this policy type does not accept. "
            f"Expected one of: {sorted(permitted_types)}. AWS validates the "
            f"Principal element when it stores a policy, so this is a document "
            f"Headroom has misread or a principal type it does not model, and "
            f"either way it cannot say whether the RCP is safe to attach here."
        )

    named = read_principal(principal.get("AWS", []), permitted_types, resource_description)

    return PrincipalReading(
        account_ids=named.account_ids,
        has_wildcard=named.has_wildcard,
        has_non_account_principals=bool(
            set(principal.keys()) & NON_ACCOUNT_PRINCIPAL_TYPES
        ),
    )
