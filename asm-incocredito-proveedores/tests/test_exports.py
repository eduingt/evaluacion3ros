import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generate_vex_export import build_vex_doc
from generate_sarif_export import _issue_to_result, build_sarif_log
from generate_sbom_export import build_sbom_doc

JUSTIFICACIONES = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def asm_con(cves):
    return {
        "generated_utc": "2026-10-13T00:00:00Z",
        "providers": [{"domain": "www.incocredito.com.co", "cve_findings": cves}],
    }


class VexTest(unittest.TestCase):
    def test_estructura_base(self):
        doc = build_vex_doc(asm_con([]))
        for k in ("@context", "@id", "author", "timestamp", "version", "statements"):
            self.assertIn(k, doc)
        self.assertEqual(doc["statements"], [])

    def test_kev_es_affected(self):
        doc = build_vex_doc(asm_con([
            {"id": "CVE-2024-1234", "title": "Critico", "risk_score": 9.1,
             "in_kev": True, "epss_score": 0.9, "product": "nginx", "port": "443"},
        ]))
        st = doc["statements"][0]
        self.assertEqual(st["status"], "affected")
        self.assertIn("action_statement", st)
        self.assertIn("KEV", st["action_statement"])

    def test_riesgo_bajo_es_not_affected(self):
        doc = build_vex_doc(asm_con([
            {"id": "CVE-2023-0001", "title": "Menor", "risk_score": 2.0, "product": "x", "port": "80"},
        ]))
        st = doc["statements"][0]
        self.assertEqual(st["status"], "not_affected")
        self.assertIn(st["justification"], JUSTIFICACIONES)

    def test_riesgo_medio_es_under_investigation(self):
        doc = build_vex_doc(asm_con([
            {"id": "CVE-2023-0002", "title": "Medio", "risk_score": 5.5, "product": "x", "port": "80"},
        ]))
        self.assertEqual(doc["statements"][0]["status"], "under_investigation")


class SariTest(unittest.TestCase):
    def test_estructura_base(self):
        log = build_sarif_log({"generated_utc": "2026-10-13T00:00:00Z", "providers": []})
        self.assertEqual(log["version"], "2.1.0")
        self.assertTrue(log["runs"][0]["tool"]["driver"]["rules"])
        self.assertEqual(log["runs"][0]["results"], [])

    def test_issue_to_result_usa_severity_canonica(self):
        r = _issue_to_result({"id": "x", "desc": "d", "level": "alta"}, "dom", "T")
        self.assertEqual(r["level"], "error")
        r = _issue_to_result({"id": "x", "gravedad": "baja"}, "dom", "T")
        self.assertEqual(r["level"], "note")
        r = _issue_to_result({"id": "x"}, "dom", "T")
        self.assertEqual(r["level"], "warning")


class SbomTest(unittest.TestCase):
    def test_estructura_y_componentes(self):
        doc = build_sbom_doc()
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertTrue(doc["components"])
        for c in doc["components"]:
            for k in ("bom-ref", "type", "name", "version"):
                self.assertIn(k, c)
        purls = [c["purl"] for c in doc["components"] if "purl" in c]
        self.assertTrue(any(p.startswith("pkg:pypi/requests@") for p in purls))
        self.assertEqual(doc["properties"]["component_count"], len(doc["components"]))


if __name__ == "__main__":
    unittest.main()
