import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm_scan import HTTPProbe, TLSProbe, apex_of


class ApexTest(unittest.TestCase):
    def test_www_strip(self):
        self.assertEqual(apex_of("www.bigsoluciones.com"), "bigsoluciones.com")
        self.assertEqual(apex_of("www.incocredito.com.co"), "incocredito.com.co")

    def test_sin_www_intacto(self):
        self.assertEqual(apex_of("bigsoluciones.com"), "bigsoluciones.com")
        self.assertEqual(apex_of("portal.cliente.com"), "portal.cliente.com")


class ProbeDefaultsTest(unittest.TestCase):
    def test_tls_sin_chain_issue(self):
        t = TLSProbe(False, None, None, None, None, None, None, [], None)
        self.assertFalse(t.chain_issue)

    def test_https_verificado_por_defecto(self):
        h = HTTPProbe(None, None, False, [], {}, None, None, None, None, None, None, None, None, None)
        self.assertTrue(h.verified)


if __name__ == "__main__":
    unittest.main()
