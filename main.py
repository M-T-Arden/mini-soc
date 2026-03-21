from pathlib import Path
import argparse
from datetime import datetime

from config import LOG_PATH, REPORT_PATH
from core.engine import run_detection
from core.parser import load_logs
from core.report import build_incident, save_incident
from core.metrics import calculate_metrics, print_metrics_report


def generate_report(alerts):
    if not alerts:
        print("No suspicious activity detected.")
        return

    print("\n=== SECURITY ALERT REPORT ===\n")
    for i, alert in enumerate(alerts, start=1):
        print(f"[{i}] {alert.type} | {alert.severity}")
        print(f"User: {alert.user}")
        print(f"IP: {alert.src_ip}")
        print(f"Details: {alert.message}")
        print("-" * 40)


def create_output_path(input_path, output_dir):
    input_path = Path(input_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_name = f"{input_path.stem}_analysis_report_{timestamp}.json"
    return Path(output_dir) / output_name


def main():
    parser = argparse.ArgumentParser(description="Run mini SOC detection")
    parser.add_argument("--input", "-i", default=LOG_PATH, help="Input log file path")
    parser.add_argument("--output_dir", "-o", default=REPORT_PATH.parent, help="Output directory")
    parser.add_argument("--metrics", action="store_true", help="Show detailed metrics")
    args = parser.parse_args()

    input_file = Path(args.input)
    if not input_file.exists():
        raise FileNotFoundError(f"Input log file not found: {input_file}")

    logs = load_logs(input_file)
    raw_alerts, deduped_alerts = run_detection(logs)

    if args.metrics:
        metrics = calculate_metrics(raw_alerts, deduped_alerts)
        print_metrics_report(metrics)
    else:
        generate_report(deduped_alerts)

    # Always save incident summary to output directory for archival and downstream analysis
    output_path = create_output_path(input_file, args.output_dir)
    incident = build_incident(deduped_alerts, input_file)
    save_incident(incident, output_path)


if __name__ == "__main__":
    main()
