"""Semantic memory — lightweight vector-based knowledge retrieval.

Uses a simple cosine similarity approach with cached embeddings.
Embeddings can be generated via any callable, including the Gemini API.
Falls back to keyword-based matching when no embedding function is provided.
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SemanticMatch:
    """A single semantic search result."""

    text: str
    metadata: dict
    score: float = 0.0


class SemanticMemory:
    """Lightweight vector store with cosine similarity search.

    Parameters
    ----------
    embed_fn : callable or None
        Function that takes a string and returns a list[float] embedding.
        If None, falls back to keyword-based matching.
    cache_path : Path or None
        Path to persist the index to disk.
    """

    def __init__(self, embed_fn=None, cache_path: Path | None = None):
        self.embed_fn = embed_fn
        self.cache_path = cache_path
        self._index: list[dict] = []
        # {"text": str, "embedding": list[float], "metadata": dict}

    def add(self, text: str, metadata: dict | None = None) -> None:
        """Add a document to the semantic index.

        Parameters
        ----------
        text : str
            The document text to index.
        metadata : dict, optional
            Associated metadata (e.g., source, slug, tags).
        """
        if not text or not text.strip():
            return

        embedding = self._get_embedding(text)
        self._index.append({
            "text": text.strip(),
            "embedding": embedding,
            "metadata": metadata or {},
        })

    def add_many(self, documents: list[dict]) -> None:
        """Add multiple documents at once.

        Parameters
        ----------
        documents : list[dict]
            Each dict should have "text" and optionally "metadata".
        """
        for doc in documents:
            self.add(doc.get("text", ""), doc.get("metadata"))

    def search(self, query: str, top_k: int = 5) -> list[SemanticMatch]:
        """Search the index using cosine similarity.

        Parameters
        ----------
        query : str
            The search query.
        top_k : int
            Number of results to return.

        Returns
        -------
        list[SemanticMatch]
            Top matching documents sorted by similarity score.
        """
        if not self._index or not query.strip():
            return []

        query_embedding = self._get_embedding(query)

        if not query_embedding:
            # Fallback: keyword-based matching
            return self._keyword_search(query, top_k)

        scored = []
        for entry in self._index:
            if not entry.get("embedding"):
                continue
            score = _cosine_similarity(query_embedding, entry["embedding"])
            scored.append(SemanticMatch(
                text=entry["text"],
                metadata=entry.get("metadata", {}),
                score=score,
            ))

        scored.sort(key=lambda m: m.score, reverse=True)
        return scored[:top_k]

    def _keyword_search(self, query: str, top_k: int) -> list[SemanticMatch]:
        """Fallback keyword-based search when no embedding function is available."""
        query_terms = set(query.lower().split())
        if not query_terms:
            return []

        scored = []
        for entry in self._index:
            text_lower = entry["text"].lower()
            text_terms = set(text_lower.split())
            overlap = len(query_terms & text_terms)
            if overlap > 0:
                score = overlap / max(len(query_terms), 1)
                scored.append(SemanticMatch(
                    text=entry["text"],
                    metadata=entry.get("metadata", {}),
                    score=score,
                ))

        scored.sort(key=lambda m: m.score, reverse=True)
        return scored[:top_k]

    def _get_embedding(self, text: str) -> list[float]:
        """Get embedding vector using the configured function."""
        if not self.embed_fn:
            return []
        try:
            return self.embed_fn(text)
        except Exception:
            return []

    @property
    def count(self) -> int:
        """Number of documents in the index."""
        return len(self._index)

    def clear(self) -> None:
        """Clear the entire index."""
        self._index.clear()

    def save(self) -> None:
        """Persist the index to disk as JSON."""
        if not self.cache_path:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        # Save without embeddings if they are large (save space)
        data = []
        for entry in self._index:
            data.append({
                "text": entry["text"],
                "metadata": entry.get("metadata", {}),
                "embedding": entry.get("embedding", []),
            })
        self.cache_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, cache_path: Path, embed_fn=None) -> "SemanticMemory":
        """Restore from a persisted index.

        Parameters
        ----------
        cache_path : Path
            Path to the saved index file.
        embed_fn : callable, optional
            Embedding function for new queries.

        Returns
        -------
        SemanticMemory
            A restored semantic memory instance.
        """
        memory = cls(embed_fn=embed_fn, cache_path=cache_path)
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                for entry in data:
                    memory._index.append({
                        "text": entry.get("text", ""),
                        "embedding": entry.get("embedding", []),
                        "metadata": entry.get("metadata", {}),
                    })
            except (json.JSONDecodeError, OSError):
                pass
        return memory

    def index_knowledge_store(self, knowledge_store) -> int:
        """Index all cases from a KnowledgeStore for semantic search.

        Parameters
        ----------
        knowledge_store : KnowledgeStore
            The knowledge store containing cases to index.

        Returns
        -------
        int
            Number of documents indexed.
        """
        count = 0
        for case in knowledge_store.cases:
            # Build a rich text representation of the case
            parts = [case.title, case.summary or ""]
            parts.extend(case.signals[:5])
            parts.extend(case.techniques[:3])
            parts.extend(case.services[:3])
            parts.extend(case.actions[:3])
            text = " ".join(p for p in parts if p)

            if text.strip():
                self.add(text, metadata={
                    "slug": case.slug,
                    "platform": case.platform,
                    "title": case.title,
                    "summary": case.summary,
                })
                count += 1

        return count


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Parameters
    ----------
    vec_a, vec_b : list[float]
        Two vectors of the same dimension.

    Returns
    -------
    float
        Cosine similarity in [-1, 1], or 0 if either vector is zero.
    """
    if len(vec_a) != len(vec_b) or not vec_a:
        return 0.0

    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)
