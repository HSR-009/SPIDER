"""
Unit tests for Person_A/pipeline/make_replay_fixtures.py
"""

import tempfile
import unittest
from pathlib import Path

from Person_A.pipeline.make_replay_fixtures import make_replay_fixtures
from spider_contract.validate import schema_errors, semantic_errors, load_schema
import json


class TestMakeReplayFixtures(unittest.TestCase):
    def test_fixture_generation_and_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            generated = make_replay_fixtures(tmpdir)
            self.assertEqual(len(generated), 10)
            for path in generated:
                self.assertTrue(path.exists())
                record = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(record["record_origin"], "replay")
                self.assertEqual(record["target"]["kind"], "archive")
                self.assertEqual(schema_errors(record), [])
                self.assertEqual(semantic_errors(record), [])


if __name__ == "__main__":
    unittest.main()

