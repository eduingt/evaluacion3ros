import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llm_guardrails


class GuardrailsTest(unittest.TestCase):
    def test_redact_api_key(self):
        os.environ["LLM_API_KEY"] = "secreto-xyz-123"
        try:
            out = llm_guardrails.redact("fallo con key secreto-xyz-123 en stdout")
            self.assertNotIn("secreto-xyz-123", out)
            self.assertIn("[REDACTED]", out)
        finally:
            del os.environ["LLM_API_KEY"]

    def test_redact_patrones(self):
        out = llm_guardrails.redact("token sk-abcdef123456 y Bearer abcDEF123")
        self.assertNotIn("sk-abcdef123456", out)
        self.assertNotIn("Bearer abcDEF123", out)

    def test_redact_vacio_no_falla(self):
        self.assertEqual(llm_guardrails.redact(None), "")
        self.assertEqual(llm_guardrails.redact(""), "")

    def test_assess_presupuesto(self):
        base = {"test_level": 3, "mode": "standard",
                "run_record": {"llm_usage": {"total_cost_usd": 1.0}}}
        os.environ["STRIX_BUDGET_USD"] = "5"
        try:
            a = llm_guardrails.assess(base)
            self.assertFalse(a["over_budget"])
            self.assertTrue(a["mode_allowed"])
            base["run_record"]["llm_usage"]["total_cost_usd"] = 99.0
            self.assertTrue(llm_guardrails.assess(base)["over_budget"])
        finally:
            del os.environ["STRIX_BUDGET_USD"]

    def test_assess_modo_no_permitido(self):
        a = llm_guardrails.assess({"test_level": 2, "mode": "deep", "run_record": {}})
        self.assertFalse(a["mode_allowed"])


if __name__ == "__main__":
    unittest.main()
