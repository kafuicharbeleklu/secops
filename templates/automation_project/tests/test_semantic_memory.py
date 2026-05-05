"""Tests for semantic_memory — vector-based knowledge retrieval."""

import json
import math
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.semantic_memory import SemanticMemory, SemanticMatch, _cosine_similarity


class TestCosineSimilarity(unittest.TestCase):
    """Test the cosine similarity function."""

    def test_identical_vectors(self):
        vec = [1.0, 2.0, 3.0]
        self.assertAlmostEqual(_cosine_similarity(vec, vec), 1.0)

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        self.assertAlmostEqual(_cosine_similarity(a, b), 0.0)

    def test_opposite_vectors(self):
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        self.assertAlmostEqual(_cosine_similarity(a, b), -1.0)

    def test_empty_vectors(self):
        self.assertEqual(_cosine_similarity([], []), 0.0)

    def test_mismatched_dimensions(self):
        self.assertEqual(_cosine_similarity([1.0], [1.0, 2.0]), 0.0)

    def test_zero_vector(self):
        self.assertEqual(_cosine_similarity([0.0, 0.0], [1.0, 2.0]), 0.0)


class TestSemanticMemoryKeyword(unittest.TestCase):
    """Test SemanticMemory with keyword-based fallback (no embedding function)."""

    def setUp(self):
        self.memory = SemanticMemory()

    def test_add_and_count(self):
        self.memory.add("Apache 2.4 path traversal vulnerability")
        self.memory.add("OpenSSH brute force attack")
        self.assertEqual(self.memory.count, 2)

    def test_add_empty_text(self):
        self.memory.add("")
        self.memory.add("  ")
        self.assertEqual(self.memory.count, 0)

    def test_keyword_search(self):
        self.memory.add("Apache 2.4 path traversal vulnerability", {"type": "web"})
        self.memory.add("OpenSSH brute force attack", {"type": "ssh"})
        self.memory.add("SMB null session enumeration", {"type": "smb"})

        results = self.memory.search("apache path traversal")
        self.assertGreater(len(results), 0)
        # The Apache entry should score highest
        self.assertIn("Apache", results[0].text)

    def test_keyword_search_empty_query(self):
        self.memory.add("test document")
        results = self.memory.search("")
        self.assertEqual(len(results), 0)

    def test_keyword_search_no_match(self):
        self.memory.add("Apache vulnerability")
        results = self.memory.search("completely unrelated query xyz")
        self.assertEqual(len(results), 0)

    def test_top_k_limit(self):
        for i in range(10):
            self.memory.add(f"document {i} about security")
        results = self.memory.search("security", top_k=3)
        self.assertLessEqual(len(results), 3)

    def test_clear(self):
        self.memory.add("test")
        self.memory.clear()
        self.assertEqual(self.memory.count, 0)


class TestSemanticMemoryWithEmbeddings(unittest.TestCase):
    """Test SemanticMemory with a mock embedding function."""

    def _mock_embed(self, text):
        """Simple mock: hash-based embedding for deterministic tests."""
        tokens = text.lower().split()
        # Create a fixed-dimension vector from word hashes
        vec = [0.0] * 8
        for token in tokens:
            h = hash(token) % 8
            vec[h] += 1.0
        # Normalize
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def setUp(self):
        self.memory = SemanticMemory(embed_fn=self._mock_embed)

    def test_semantic_search_with_embeddings(self):
        self.memory.add("Apache web server path traversal", {"type": "web"})
        self.memory.add("OpenSSH brute force credentials", {"type": "ssh"})

        results = self.memory.search("web server vulnerability")
        self.assertGreater(len(results), 0)
        self.assertIsInstance(results[0], SemanticMatch)
        self.assertIsInstance(results[0].score, float)

    def test_search_returns_metadata(self):
        self.memory.add("test document", {"slug": "test-case", "platform": "htb"})
        results = self.memory.search("test")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].metadata.get("slug"), "test-case")


class TestSemanticMemoryPersistence(unittest.TestCase):
    """Test saving and loading the semantic index."""

    def test_save_and_load(self):
        with TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "index.json"
            memory = SemanticMemory(cache_path=cache_path)
            memory.add("Apache path traversal", {"slug": "apache-vuln"})
            memory.add("SSH brute force", {"slug": "ssh-brute"})
            memory.save()

            # Load into a new instance
            loaded = SemanticMemory.load(cache_path)
            self.assertEqual(loaded.count, 2)

    def test_load_missing_file(self):
        with TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "nonexistent.json"
            loaded = SemanticMemory.load(cache_path)
            self.assertEqual(loaded.count, 0)

    def test_load_corrupt_file(self):
        with TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "corrupt.json"
            cache_path.write_text("{bad json", encoding="utf-8")
            loaded = SemanticMemory.load(cache_path)
            self.assertEqual(loaded.count, 0)

    def test_add_many(self):
        memory = SemanticMemory()
        docs = [
            {"text": "doc one", "metadata": {"id": 1}},
            {"text": "doc two", "metadata": {"id": 2}},
        ]
        memory.add_many(docs)
        self.assertEqual(memory.count, 2)


class TestSemanticMemoryKnowledgeStore(unittest.TestCase):
    """Test indexing from a KnowledgeStore."""

    def test_index_knowledge_store(self):
        # Create a mock KnowledgeStore
        class MockCase:
            def __init__(self, slug, title, summary):
                self.slug = slug
                self.title = title
                self.summary = summary
                self.platform = "htb"
                self.signals = ["port 80 open"]
                self.techniques = ["path traversal"]
                self.services = ["Apache"]
                self.actions = ["run gobuster"]

        class MockStore:
            @property
            def cases(self):
                return [
                    MockCase("test-1", "Test Case 1", "Web app pentest"),
                    MockCase("test-2", "Test Case 2", "SSH brute force"),
                ]

        memory = SemanticMemory()
        count = memory.index_knowledge_store(MockStore())
        self.assertEqual(count, 2)
        self.assertEqual(memory.count, 2)

    def test_index_empty_store(self):
        class EmptyStore:
            @property
            def cases(self):
                return []

        memory = SemanticMemory()
        count = memory.index_knowledge_store(EmptyStore())
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
