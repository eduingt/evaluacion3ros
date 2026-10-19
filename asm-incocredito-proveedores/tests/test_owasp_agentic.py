import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import owasp_agentic


class OwaspAgenticTest(unittest.TestCase):
    def test_ids_y_estructura(self):
        self.assertEqual(len(owasp_agentic.OWASP_AGENTIC), 10)
        r = owasp_agentic.evaluate_provider({})
        self.assertIn("overall_grade", r)
        self.assertEqual(len(r["risks"]), 10)

    def test_https_int_no_falla(self):
        r = owasp_agentic.evaluate_provider({"https": 200, "tls": {}, "mx_count": 0})
        self.assertNotIn("error", r)

    def test_https_dict_con_status_ok(self):
        p = {
            "https": {"status": 200, "headers": {"strict-transport-security": "max-age=1"}},
            "tls": {},
            "mx_count": 0,
        }
        r = owasp_agentic.evaluate_provider(p)
        https = []
        for rd in r["risks"].values():
            https += [f for f in rd["findings"] if f["id"] == "https_missing"]
        self.assertEqual(https, [])


if __name__ == "__main__":
    unittest.main()
