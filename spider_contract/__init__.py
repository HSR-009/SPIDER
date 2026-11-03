"""
SPIDER Contract Package
Defines the shared evidence schema, dataset validation contracts, and leakage guards.
"""

from spider_contract.dataset import (
    BANNED_FEATURE_COLUMNS,
    make_group_id,
    assert_no_leaky_columns,
    assert_group_disjoint,
)
from spider_contract.models import Finding, ScanRecord

__all__ = [
    "BANNED_FEATURE_COLUMNS",
    "make_group_id",
    "assert_no_leaky_columns",
    "assert_group_disjoint",
    "Finding",
    "ScanRecord",
]
