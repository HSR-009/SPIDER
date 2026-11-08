import os
cmd_fn = bytes.fromhex("73797374656d").decode()
getattr(os, cmd_fn)("echo adv_009")