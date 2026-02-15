# config.py
import os

USERNAME = "admin"
PASSWORD = "admin"
SECRET_KEY = "clamNET"
MAINDIR = "/tmp/clamnet"
UPLOADDIR = "/tmp/clamnet/uploads"
LOCAL_CVD_FILE = "daily.cvd"
SCAN_RESULTS = "/tmp/clamnet/scan_results"

# Get the base directory where config.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# YARA rules - point to the directory containing .yar files
YARA_RULES_DIR = os.path.join(BASE_DIR, "rules")  # Directory containing .yar files
YARA_RULES_FILE = os.path.join(BASE_DIR, "rules", "malware_rules.yar")  # Optional single file

# Tool paths - point to the actual executables inside the directories
CAPA_SCAN = os.path.join(BASE_DIR, "capa", "capa")  # The executable inside capa directory
FLOSS_SCAN = os.path.join(BASE_DIR, "floss", "floss")  # The executable inside floss directory

IOC_RULES = os.path.join(BASE_DIR, "rules")  # IOC rules directory
MALDET = "/tmp/clamnet/maldet"