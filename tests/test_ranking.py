"""Unit tests for Information Retrieval, Learning-to-Rank, and NDCG@k / MRR evaluation."""

import unittest
from dns_scanner.ranking import (
    DomainIRRanker,
    ndcg_at_k,
    mrr_score,
    precision_at_k,
    recall_at_k,
    evaluate_ir_benchmark,
)


class TestDomainIRRanking(unittest.TestCase):
    def test_ir_metrics_ndcg_mrr_precision_recall(self):
        relevances = [3.0, 2.0, 1.0, 0.0, 0.0]
        perfect = [0.95, 0.85, 0.70, 0.20, 0.10]
        inverted = [0.10, 0.20, 0.70, 0.85, 0.95]
        rel_mask = [True, True, False, False, False]

        self.assertAlmostEqual(ndcg_at_k(perfect, relevances, k=3), 1.0, places=5)
        self.assertLess(ndcg_at_k(inverted, relevances, k=3), 0.5)
        self.assertAlmostEqual(mrr_score(perfect, rel_mask), 1.0, places=5)
        self.assertAlmostEqual(mrr_score([0.1, 0.9, 0.8, 0.2, 0.0], rel_mask), 1.0, places=5)
        self.assertAlmostEqual(mrr_score([0.1, 0.2, 0.9, 0.8, 0.0], rel_mask), 1.0 / 3.0, places=5)
        self.assertAlmostEqual(precision_at_k(perfect, rel_mask, k=2), 1.0, places=5)
        self.assertAlmostEqual(recall_at_k(perfect, rel_mask, k=1), 0.5, places=5)

    def test_hybrid_domain_ranker_and_offline_benchmark(self):
        candidates = [
            "cloudmesh.io",
            "datacloud.io",
            "xqzvbnm.io",
            "quantflow.io",
            "flowquant.io",
            "zzkkqqp.io",
        ]
        ranker = DomainIRRanker(candidates)
        top_cloud = ranker.rank("cloud mesh data", top_k=2)
        top_names = {r.domain for r in top_cloud}
        self.assertEqual(top_names, {"cloudmesh.io", "datacloud.io"})

        benchmark = [
            ("cloud data mesh", [3.0, 3.0, 0.0, 0.5, 0.5, 0.0]),
            ("quant flow", [0.5, 0.5, 0.0, 3.0, 3.0, 0.0]),
        ]
        metrics = evaluate_ir_benchmark(ranker, benchmark, k=2)
        self.assertGreaterEqual(metrics["ndcg@2"], 0.95)
        self.assertAlmostEqual(metrics["mrr"], 1.0, places=4)
        self.assertAlmostEqual(metrics["precision@2"], 1.0, places=4)


if __name__ == "__main__":
    unittest.main()
