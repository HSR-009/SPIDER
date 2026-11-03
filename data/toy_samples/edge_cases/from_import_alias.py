from os import system as run_cmd
from subprocess import run as execute
from base64 import b64decode as decode_data

run_cmd("whoami")
execute(["whoami"])
data = decode_data("SGVsbG8=")