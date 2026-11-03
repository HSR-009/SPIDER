import base64
import codecs
import random


def base64_disguise(payload_code):
    encoded = base64.b64encode(
        payload_code.encode("utf-8")
    ).decode("ascii")

    return (
        "import base64\n"
        f"encoded_data = {encoded!r}\n"
        "decoded_code = base64.b64decode(encoded_data)\n"
        "exec(decoded_code)"
    )


def rot13_disguise(payload_code):
    encoded = codecs.encode(payload_code, "rot_13")

    return (
        "import codecs\n"
        f"encoded_data = {encoded!r}\n"
        "decoded_code = codecs.decode(encoded_data, 'rot_13')\n"
        "exec(decoded_code)"
    )


def getattr_disguise(module, func_name, args_code=""):
    parts = [func_name[i:i + 2] for i in range(0, len(func_name), 2)]
    reconstructed_name = " + ".join(repr(part) for part in parts)

    return (
        f"import {module}\n"
        f"function_name = {reconstructed_name}\n"
        f"getattr({module}, function_name)({args_code})"
    )


def delay_disguise(payload_code, trigger_count=3):
    indented_payload = "\n".join(
        "    " + line for line in payload_code.splitlines()
    )

    return (
        "counter = 0\n"
        "counter += 1\n"
        f"if counter >= {trigger_count}:\n"
        f"{indented_payload}"
    )


def string_split_disguise(sensitive_word):
    if not sensitive_word:
        return "''"

    parts = []
    index = 0

    while index < len(sensitive_word):
        remaining = len(sensitive_word) - index
        size = random.randint(1, min(3, remaining))
        parts.append(sensitive_word[index:index + size])
        index += size

    return " + ".join(repr(part) for part in parts)