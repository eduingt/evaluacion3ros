import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import generate_b7_unified_report as b7


def prov(dns):
    return {"domain": "www.bigsoluciones.com", "dns": dns}


class CatalogoDnsTest(unittest.TestCase):
    def test_dmarc_dkim_solo_con_mx(self):
        mx = [{"preference": "0", "exchange": "x.mail.protection.outlook.com"}]
        r = b7.b7_provider_scores(
            prov({"mx_records": mx, "spf_record": "v=spf1 -all",
                  "dmarc_record": None, "dkim_records": []}), [])
        keys = [i["key"] for i in r["by_factor"].get("dns", [])]
        self.assertIn("dmarc_missing", keys)
        self.assertIn("dkim_missing", keys)
        self.assertNotIn("spf_missing", keys)

    def test_reputacion_terceros(self):
        scr = {"dnsbl": [{"ip": "192.178.155.97", "dnsbl": "zen.spamhaus.org"}], "urlhaus": []}
        r = b7.b7_provider_scores(dict(prov({}), supply_chain_reputation=scr), [])
        keys = [i["key"] for i in r["by_factor"].get("iprep", [])]
        self.assertIn("supply_reputation", keys)
        r2 = b7.b7_provider_scores(prov({}), [])
        keys2 = [i["key"] for i in r2["by_factor"].get("iprep", [])]
        self.assertNotIn("supply_reputation", keys2)

    def test_sin_mx_no_exige_dmarc_dkim(self):
        r = b7.b7_provider_scores(
            prov({"mx_records": [], "spf_record": None,
                  "dmarc_record": None, "dkim_records": []}), [])
        keys = [i["key"] for i in r["by_factor"].get("dns", [])]
        self.assertIn("spf_missing", keys)
        self.assertNotIn("dmarc_missing", keys)
        self.assertNotIn("dkim_missing", keys)


if __name__ == "__main__":
    unittest.main()
