import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import owasp_web


def proveedor_inseguro():
    return {
        "https": {"status": 200, "headers": {}},
        "tls": {"negotiated_version": "TLSv1.2", "tls13_only_ok": False},
        "spf_dmarc": "SPF:missing DMARC:-",
        "mx_count": 1,
        "starttls_ok": False,
        "dnssec_ok": False,
        "cve_finding_count": 1,
        "shadow_api_count": 2,
        "puertos": "80:open",
    }


class OwaspWebTest(unittest.TestCase):
    def test_ids_y_estructura(self):
        self.assertEqual(len(owasp_web.OWASP_WEB), 10)
        self.assertEqual(owasp_web.OWASP_WEB[0]["id"], "W-01")
        r = owasp_web.evaluate_provider({})
        self.assertEqual(len(r["risks"]), 10)
        self.assertLess(r["overall_compliance"], 100.0)
        self.assertGreater(r["risks"]["W-02"]["finding_count"], 0)

    def test_proveedor_inseguro_baja_compliance(self):
        r = owasp_web.evaluate_provider(proveedor_inseguro())
        self.assertLess(r["overall_compliance"], 100.0)
        self.assertGreater(r["risks"]["W-02"]["finding_count"], 0)
        self.assertGreater(r["risks"]["W-04"]["finding_count"], 0)
        self.assertGreater(r["risks"]["W-06"]["finding_count"], 0)
        self.assertGreater(r["risks"]["W-01"]["finding_count"], 0)

    def test_https_int_no_falla(self):
        p = dict(proveedor_inseguro(), https=200)
        r = owasp_web.evaluate_provider(p)
        self.assertNotIn("error", r)
        self.assertIn("W-02", r["risks"])

    def test_https_dict_con_status_ok(self):
        p = dict(
            proveedor_inseguro(),
            https={"status": 200, "headers": {"strict-transport-security": "max-age=31536000"}},
        )
        r = owasp_web.evaluate_provider(p)
        ids_w02 = [f["id"] for f in r["risks"]["W-02"]["findings"]]
        self.assertNotIn("missing_hsts", ids_w02)
        self.assertIn("missing_csp", ids_w02)


if __name__ == "__main__":
    unittest.main()
