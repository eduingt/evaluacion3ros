#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests Fase P2 — reproducibilidad de scores B3."""
import json
import unittest
from pathlib import Path

import generate_b3_unified_report as b3
from precia_scorecard import factor_scores as pscores, overall_score as poverall

ROOT = Path(__file__).resolve().parent

class TestB3Scores(unittest.TestCase):
    def test_domain_score_reproducible(self):
        data = json.loads((ROOT / "dashboard_workspace" / "last" / "asm_report.json").read_text(encoding="utf-8"))
        p = data["providers"][0]
        s1 = b3.domain_score(p)
        s2 = b3.domain_score(p)
        self.assertEqual(s1, s2)
        self.assertGreaterEqual(s1, 0)
        self.assertLessEqual(s1, 100)

    def test_score_general_reproducible(self):
        data = json.loads((ROOT / "dashboard_workspace" / "last" / "asm_report.json").read_text(encoding="utf-8"))
        f1 = b3.compute_factores(data["providers"])
        f2 = b3.compute_factores(data["providers"])
        self.assertEqual(f1, f2)
        sg = int(sum(x["score"] for x in f1) / len(f1))
        self.assertGreaterEqual(sg, 0)
        self.assertLessEqual(sg, 100)

    def test_overall_contribucion_suma(self):
        data = json.loads((ROOT / "dashboard_workspace" / "last" / "asm_report.json").read_text(encoding="utf-8"))
        p = data["providers"][0]
        sc = pscores(p)
        ov = poverall(sc)
        total_w = sum(b3._PRECIA_WEIGHTS.get(k, 1.0) for k in sc)
        suma = round(sum(int(sc[k]) * b3._PRECIA_WEIGHTS.get(k, 1.0) / total_w for k in sc), 1)
        self.assertAlmostEqual(suma, ov, delta=0.5)

    def test_formula_version_present(self):
        self.assertTrue(hasattr(b3, "FORMULA_VERSION"))
        self.assertTrue(hasattr(b3, "FORMULA_DATE"))
        self.assertIn("B3-v", b3.FORMULA_VERSION)

if __name__ == "__main__":
    unittest.main()
