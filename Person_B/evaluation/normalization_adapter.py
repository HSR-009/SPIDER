"""Normalization Adapter for Person C's AST Normalization Module.

Wraps spider.normalize without inventing new behavior or modifying Person C's
implementation. Provides error handling, change tracking, and clear documentation
of capabilities and limitations.
"""
from __future__ import annotations

import ast
from typing import Any, Dict, Tuple

try:
    from spider.normalize import (
        ConstantFoldStringConcat,
        DecodeLiteralBase64,
        GetattrToAttribute,
        ResolveImportAliases,
        normalize_source,
    )
    NORMALIZATION_AVAILABLE = True
except ImportError:
    NORMALIZATION_AVAILABLE = False
    normalize_source = None  # type: ignore


# Documentation of Person C's four AST normalization rules (from adv-batch-v1)
NORMALIZATION_RULES = [
    {
        "id": "R1_string_concat",
        "name": "ConstantFoldStringConcat",
        "description": "Folds chains of constant string additions ('sys' + 'tem' -> 'system')",
        "supported": True,
    },
    {
        "id": "R2_import_alias",
        "name": "ResolveImportAliases",
        "description": "Rewrites aliased imports (import os as x; x.system -> os.system)",
        "supported": True,
        "limitation": "Only handles 'import X as Y'; does not handle 'from X import Y as Z'",
    },
    {
        "id": "R3_decode_base64",
        "name": "DecodeLiteralBase64",
        "description": "Statically decodes constant base64 literals into bytes literals",
        "supported": True,
        "limitation": "Only handles literal base64 strings in base64.b64decode calls",
    },
    {
        "id": "R4_getattr_attribute",
        "name": "GetattrToAttribute",
        "description": "Rewrites 2-argument constant getattr calls (getattr(os, 'system') -> os.system)",
        "supported": True,
        "limitation": "Only handles 2-arg getattr with a valid identifier literal; leaves 3-arg untouched",
    },
]

# Explicit limitations of Person C's normalization module
MODULE_LIMITATIONS = [
    "Docstring in spider/normalize.py explicitly declares it as a placeholder / best-guess module.",
    "Does not handle 'from ... import ... as ...' alias shapes.",
    "Does not normalize ROT13 encodings (e.g. codecs.decode(..., 'rot_13')).",
    "Does not normalize dynamic imports (e.g. __import__('o' + 's')).",
    "Does not normalize character joins (e.g. join(chr)).",
    "Does not normalize hex escapes (e.g. bytes.fromhex).",
    "Does not normalize execution delay triggers.",
]


def normalize_code(source: str) -> Tuple[str, bool, str]:
    """Safely apply Person C's normalization to Python source code.
    
    Returns:
        (normalized_source, was_modified, status_message)
    
    Guarantees:
        - Never executes input code (pure AST transformation).
        - Deterministic output.
        - Fail-safe: Returns original source if normalization fails or is unavailable.
    """
    if not NORMALIZATION_AVAILABLE or normalize_source is None:
        return source, False, "Normalization module unavailable"

    try:
        normalized = normalize_source(source)
        was_modified = normalized.strip() != source.strip()
        status = "Normalized successfully" if was_modified else "No transformation applied"
        return normalized, was_modified, status
    except SyntaxError as e:
        return source, False, f"SyntaxError during normalization: {e}"
    except Exception as e:
        return source, False, f"Error during normalization: {e}"


def get_normalization_metadata() -> Dict[str, Any]:
    """Return provenance and capability metadata for Person C's normalizer."""
    return {
        "module": "spider.normalize",
        "source_tag": "adv-batch-v1",
        "available": NORMALIZATION_AVAILABLE,
        "is_official_placeholder": True,
        "rules": NORMALIZATION_RULES,
        "limitations": MODULE_LIMITATIONS,
    }
