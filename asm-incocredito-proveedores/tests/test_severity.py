import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import severity


class SeverityTest(unittest.TestCase):
    def test_normalize_es(self):
        self.assertEqual(severity.normalize("critica"), "critical")
        self.assertEqual(severity.normalize("ALTA"), "high")
        self.assertEqual(severity.normalize("Media"), "medium")
        self.assertEqual(severity.normalize("baja"), "low")

    def test_normalize_en_y_desconocido(self):
        self.assertEqual(severity.normalize("HIGH"), "high")
        self.assertEqual(severity.normalize(""), "info")
        self.assertEqual(severity.normalize("inexistente"), "info")

    def test_sarif_level(self):
        self.assertEqual(severity.sarif_level("critical"), "error")
        self.assertEqual(severity.sarif_level("alta"), "error")
        self.assertEqual(severity.sarif_level("medium"), "warning")
        self.assertEqual(severity.sarif_level("baja"), "note")
        self.assertEqual(severity.sarif_level("info"), "note")

    def test_rank_ordena(self):
        self.assertLess(severity.rank("critical"), severity.rank("high"))
        self.assertLess(severity.rank("high"), severity.rank("medium"))
        self.assertLess(severity.rank("medium"), severity.rank("low"))


if __name__ == "__main__":
    unittest.main()
