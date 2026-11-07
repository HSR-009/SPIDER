from dataclasses import dataclass, field
from typing import List

@dataclass
class Limits:
    max_files: int = 20000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_depth: int = 40
