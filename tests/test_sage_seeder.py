"""Tests for core.sage_seeder — SAGE knowledge seeder."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.sage_seeder import SageSeeder, _SEED_VERSION


class TestSageSeederFixtureGeneration(unittest.TestCase):
    """Tests for generate_seed_fixtures()."""

    def test_fixtures_exist_after_generation(self):
        """Verify that JSON fixtures were generated in data/sage_seeds/."""
        seed_dir = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
        expected = [
            "exploit_patterns.json",
            "protocol_archetypes.json",
            "token_quirks.json",
            "historical_exploits.json",
            "manifest.json",
        ]
        for fname in expected:
            fpath = seed_dir / fname
            self.assertTrue(fpath.exists(), f"Missing fixture: {fname}")

    def test_exploit_patterns_fixture_has_entries(self):
        seed_dir = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
        data = json.loads((seed_dir / "exploit_patterns.json").read_text())
        self.assertGreater(len(data), 50)
        # Each entry should have content and tags
        for entry in data[:5]:
            self.assertIn("content", entry)
            self.assertIn("tags", entry)

    def test_protocol_archetypes_fixture_has_entries(self):
        seed_dir = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
        data = json.loads((seed_dir / "protocol_archetypes.json").read_text())
        self.assertGreater(len(data), 30)
        for entry in data[:5]:
            self.assertIn("content", entry)
            self.assertIn("domain", entry)

    def test_token_quirks_fixture_has_entries(self):
        seed_dir = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
        data = json.loads((seed_dir / "token_quirks.json").read_text())
        self.assertEqual(len(data), 12)

    def test_historical_exploits_fixture_has_entries(self):
        seed_dir = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
        data = json.loads((seed_dir / "historical_exploits.json").read_text())
        self.assertGreater(len(data), 10)

    def test_manifest_has_checksums(self):
        seed_dir = Path(__file__).resolve().parent.parent / "data" / "sage_seeds"
        manifest = json.loads((seed_dir / "manifest.json").read_text())
        self.assertIn("version", manifest)
        self.assertIn("checksums", manifest)
        self.assertIn("exploit_patterns.json", manifest["checksums"])


class TestSageSeederSeedAll(unittest.TestCase):
    """Tests for seed_all() with mocked SageClient."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.recall.return_value = []
        self.mock_client.remember.return_value = {"status": "ok"}

    def test_seed_all_loads_all_fixtures(self):
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        counts = seeder.seed_all(force=True)

        self.assertIn("exploits", counts)
        self.assertIn("archetypes", counts)
        self.assertIn("token_quirks", counts)
        self.assertIn("historical_exploits", counts)
        self.assertGreater(counts["exploits"], 50)
        self.assertGreater(counts["archetypes"], 30)
        self.assertEqual(counts["token_quirks"], 12)

        # Should have called remember many times
        self.assertGreater(self.mock_client.remember.call_count, 100)

    def test_seed_all_skips_if_version_current(self):
        """If SAGE already has the current seed version, skip."""
        self.mock_client.recall.return_value = [
            {"content": f"Aether knowledge base seeded: version {_SEED_VERSION}"}
        ]
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        result = seeder.seed_all(force=False)
        self.assertEqual(result["status"], "already_seeded")
        # Should NOT have called remember (except for the recall check)
        self.mock_client.remember.assert_not_called()

    def test_seed_all_force_ignores_version(self):
        """force=True should seed even if version is current."""
        self.mock_client.recall.return_value = [
            {"content": f"version {_SEED_VERSION}"}
        ]
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        counts = seeder.seed_all(force=True)
        self.assertGreater(self.mock_client.remember.call_count, 100)

    def test_seed_all_stores_version_marker(self):
        """After seeding, should store the version marker."""
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        seeder.seed_all(force=True)

        # Find the version marker call
        version_calls = [
            c for c in self.mock_client.remember.call_args_list
            if "sage-meta" in str(c)
        ]
        self.assertTrue(len(version_calls) > 0, "Version marker not stored")


class TestSageSeederIndividualMethods(unittest.TestCase):
    """Tests for individual seed methods."""

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.remember.return_value = {"status": "ok"}

    def test_seed_exploits(self):
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        count = seeder.seed_exploits()
        self.assertGreater(count, 50)
        # Verify domain is exploit-patterns
        for call in self.mock_client.remember.call_args_list[:3]:
            self.assertEqual(call[1]["domain"], "exploit-patterns")
            self.assertEqual(call[1]["memory_type"], "fact")
            self.assertAlmostEqual(call[1]["confidence"], 0.95)

    def test_seed_archetypes(self):
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        count = seeder.seed_archetypes()
        self.assertGreater(count, 30)
        # Verify domains are protocol-specific
        domains = set()
        for call in self.mock_client.remember.call_args_list:
            domains.add(call[1]["domain"])
        self.assertTrue(any(d.startswith("protocol-") for d in domains))

    def test_seed_token_quirks(self):
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        count = seeder.seed_token_quirks()
        self.assertEqual(count, 12)

    def test_seed_historical_exploits(self):
        seeder = SageSeeder(sage_client=self.mock_client, seed_delay=0)
        count = seeder.seed_historical_exploits()
        self.assertGreater(count, 10)


class TestSageSeederGracefulDegradation(unittest.TestCase):
    """Seeder should not crash if SAGE is unavailable."""

    def test_seed_with_failing_client(self):
        mock_client = MagicMock()
        mock_client.recall.side_effect = Exception("connection refused")
        mock_client.remember.side_effect = Exception("connection refused")

        seeder = SageSeeder(sage_client=mock_client, seed_delay=0)
        # Should not raise — seed_all catches failures in _is_current_version
        # and individual seed methods just count successful calls (0)
        counts = seeder.seed_all(force=True)
        self.assertEqual(counts["exploits"], 0)

    def test_missing_fixture_file(self):
        mock_client = MagicMock()
        mock_client.remember.return_value = {}
        seeder = SageSeeder(sage_client=mock_client, seed_delay=0)
        # Try to load a nonexistent fixture
        count = seeder._seed_fixture("nonexistent.json", "test", "fact", 0.9)
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
