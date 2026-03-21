from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "logs" / "sample.json"
REPORT_PATH = BASE_DIR / "output" / "report.json"

FAILED_THRESHOLD = 3
OFF_HOURS = range(0, 6)  # 0:00 - 6:00
