"""DIR: deterministic hidden-directory ranking.

On the RootMe run the top candidate flip-flopped between /panel and /uploads
across two DirBrute passes: both are high-value (score 2), and the tie was broken
by gobuster's threaded (non-deterministic) output order. Ranking must be stable
for the same set of paths regardless of the order they arrive in.
"""
from __future__ import annotations

import itertools
import unittest

from secops_agent.core.agent import SecOpsAgent


class DirCandidateRankingTests(unittest.TestCase):
    def test_ranking_is_order_independent(self):
        paths = ["/css", "/panel", "/js", "/uploads", "/server-status"]
        rankings = {
            tuple(SecOpsAgent._rank_dir_candidates(list(perm)))
            for perm in itertools.permutations(paths)
        }
        self.assertEqual(len(rankings), 1, "ranking must be identical for every input order")

    def test_high_value_first_with_alphabetical_tiebreak(self):
        ranked = SecOpsAgent._rank_dir_candidates(["/uploads", "/server-status", "/panel", "/css"])
        self.assertEqual(ranked[0], "/panel")    # score 2, alphabetically first among the tie
        self.assertEqual(ranked[1], "/uploads")  # score 2
        self.assertLess(ranked.index("/panel"), ranked.index("/css"))  # attack surface before noise

    def test_dedupes_preserving_determinism(self):
        self.assertEqual(
            SecOpsAgent._rank_dir_candidates(["/panel", "/panel", "/uploads"]),
            ["/panel", "/uploads"],
        )


if __name__ == "__main__":
    unittest.main()
