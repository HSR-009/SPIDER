"""
transformations_ext.py
-----------------------
T06-T09: the four new evasion techniques added on Day 2, extending the
T01-T05 set already in disguises.py.

    T01 = string_split_disguise()   (existing, disguises.py)
    T02 = base64_disguise()         (existing, disguises.py)
    T03 = rot13_disguise()          (existing, disguises.py)
    T04 = getattr_disguise()        (existing, disguises.py)
    T05 = delay_disguise()          (existing, disguises.py)
    T06 = import_alias_disguise()   (new, this file)
    T07 = dunder_import_disguise()  (new, this file)
    T08 = chr_build_disguise()      (new, this file)
    T09 = hex_escape_disguise()     (new, this file)

MERGE NOTE: these functions follow the same style/signature conventions as
the existing disguises.py functions, so they can be appended directly into
that file's DISGUISE_TECHNIQUES registry. Kept as a separate file here only
so the Day 2 diff is easy to review before merging.

These specifically target the new v1.1 analyzer rules Person A documented:
__import__ / importlib with non-constant arguments, bytes.fromhex(...).decode(),
and chr() joins.
"""

import random


# ---------------------------------------------------------------------------
# T06 — Import aliasing
# ---------------------------------------------------------------------------

def import_alias_disguise(module: str, func_name: str, args_code: str,
                           alias: str = None) -> str:
    """
    Converts a direct call like `os.system(cmd)` into a call through an
    aliased import, so the literal "module.func" text never appears
    together and a scanner keying off the real module name misses it.

    Example:
        import_alias_disguise("os", "system", '"ls -la"')
        -> 'import os as _x7f\n_x7f.system("ls -la")'
    """
    if alias is None:
        alias = f"_x{random.randint(1000, 9999)}"

    return f'import {module} as {alias}\n{alias}.{func_name}({args_code})'


# ---------------------------------------------------------------------------
# T07 — __import__ / importlib indirection
# ---------------------------------------------------------------------------

def dunder_import_disguise(module: str, func_name: str, args_code: str,
                            use_importlib: bool = False) -> str:
    """
    Resolves the module through __import__() or importlib.import_module()
    instead of a normal `import` statement, so there's no static `import X`
    line a simple import-scanner could key off.

    Example:
        dunder_import_disguise("os", "system", '"ls -la"')
        -> '__import__("os").system("ls -la")'
    """
    if use_importlib:
        return (
            f'import importlib\n'
            f'importlib.import_module("{module}").{func_name}({args_code})'
        )
    return f'__import__("{module}").{func_name}({args_code})'


# ---------------------------------------------------------------------------
# T08 — chr() building
# ---------------------------------------------------------------------------

def chr_build_disguise(word: str) -> str:
    """
    Builds a sensitive word character-by-character using chr() codes
    joined together, so the literal word never appears as a string in the
    source at all.

    Example:
        chr_build_disguise("system")
        -> "''.join([chr(115), chr(121), chr(115), chr(116), chr(101), chr(109)])"
    """
    chr_calls = ", ".join(f"chr({ord(c)})" for c in word)
    return f"''.join([{chr_calls}])"


# ---------------------------------------------------------------------------
# T09 — Hex-escape strings
# ---------------------------------------------------------------------------

def hex_escape_disguise(word: str) -> str:
    """
    Represents a sensitive word as a hex string decoded via
    bytes.fromhex(...).decode(), matching the specific pattern Person A's
    v1.1 analyzer rules watch for.

    Example:
        hex_escape_disguise("system")
        -> 'bytes.fromhex("73797374656d").decode()'
    """
    hex_str = word.encode().hex()
    return f'bytes.fromhex("{hex_str}").decode()'


# ---------------------------------------------------------------------------
# Registry — matches the style of DISGUISE_TECHNIQUES in disguises.py
# ---------------------------------------------------------------------------

EXTENDED_TECHNIQUES = {
    "T06_import_alias": import_alias_disguise,
    "T07_dunder_import": dunder_import_disguise,
    "T08_chr_build": chr_build_disguise,
    "T09_hex_escape": hex_escape_disguise,
}


if __name__ == "__main__":
    print("--- T06 import_alias_disguise ---")
    print(import_alias_disguise("os", "system", '"ls -la"', alias="x"))
    print()

    print("--- T07 dunder_import_disguise (plain __import__) ---")
    print(dunder_import_disguise("os", "system", '"ls -la"'))
    print()

    print("--- T07 dunder_import_disguise (importlib) ---")
    print(dunder_import_disguise("os", "system", '"ls -la"', use_importlib=True))
    print()

    print("--- T08 chr_build_disguise ---")
    print(chr_build_disguise("system"))
    print()

    print("--- T09 hex_escape_disguise ---")
    print(hex_escape_disguise("system"))
