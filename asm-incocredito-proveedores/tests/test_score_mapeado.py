import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import generate_b6_unified_report as b6
import generate_b7_unified_report as b7


class ScoreMapeadoTest(unittest.TestCase):
    def test_b6_cubre_los_10_factores_b7(self):
        b6_keys = {k for _, k in b6._B6_SSC}
        b7_keys = {k for k, _, _ in b7.SSC_FACTORS}
        self.assertEqual(b6_keys, b7_keys)
        self.assertEqual(len(b6_keys), 10)

    def test_incidencia_vs_filas_evidencia(self):
        it = {"key": "typo", "factor": "social", "sev": "BAJA", "impact": -0.1,
              "title": "Dominios lookalike", "desc": "d", "reco": [],
              "cols": ["DOMINIO", "FECHA"], "rows": [["a.com", "hoy"], ["b.com", "hoy"], ["c.com", "hoy"]]}
        html = b7.render_evidence_table(it)
        self.assertIn("3 fila(s) de evidencia", html)
        self.assertIn("1 hallazgo = 1 incidencia", html)
        self.assertNotIn("resultado", html)
        self.assertNotIn("issue", html)
        by = b7.issues_by_factor([it])
        self.assertEqual(len(by["social"]), 1)

    def test_tarjeta_ip_propia(self):
        p = {"domain": "x.test",
             "dns": {"ip_reputation": [{"ip": "1.2.3.4", "dnsbl": "zen.spamhaus.org"}]}}
        fins = b6.build_findings(p)
        titulos = [f.get("titulo", "") for f in fins]
        self.assertTrue(any("IP propia listada" in t for t in titulos))
        card = next(f for f in fins if "IP propia listada" in f.get("titulo", ""))
        self.assertEqual(card.get("severidad"), "MEDIA")
        self.assertEqual(b6._mueve_a(card), "D · G · O")
        p2 = {"domain": "x.test", "dns": {}}
        titulos2 = [f.get("titulo", "") for f in b6.build_findings(p2)]
        self.assertFalse(any("IP propia listada" in t for t in titulos2))

    def test_mueve_a_veredicto_mueve_dgo(self):
        m = b6._mueve_a({"titulo": "Verdict SPF/DMARC SPOOFABLE en x",
                         "categoria": "CONFIGURACION DE CORREO"})
        self.assertEqual(m, "D · G · O")

    def test_b7_helper_estructura(self):
        p = {"domain": "www.incocredito.com.co", "dns": {}, "https": {"status": 200, "headers": {}}}
        r = b7.b7_provider_scores(p, [])
        self.assertEqual(set(r["scores"].keys()), {k for k, _, _ in b7.SSC_FACTORS})
        self.assertIsInstance(r["overall"], int)
        self.assertIn("issues", r)
        self.assertIn("base", r)


if __name__ == "__main__":
    unittest.main()
