# -*- coding: utf-8 -*-
import os

NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
LEAK_LOOKUP_API_KEY = os.getenv("LEAK_LOOKUP_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"