from datetime import datetime
import os


def create_report(events):
    report_folder = "reports"

    if not os.path.exists(report_folder):
        os.makedirs(report_folder)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(
        report_folder,
        f"security_report_{timestamp}.txt"
    )

    with open(report_file, "w") as file:
        file.write("===== WINDOWS MONITORING SECURITY REPORT =====\n")
        file.write(f"Generated On: {datetime.now()}\n")
        file.write("=" * 50 + "\n\n")

        if not events:
            file.write("No suspicious events detected.\n")
        else:
            for event in events:
                file.write(f"ALERT: {event}\n")

    print("\nReport generated successfully!")
    print("Report location:", report_file)


if __name__ == "__main__":

    test_events = [
        "Suspicious service path detected",
        "Unknown process detected"
    ]

    create_report(test_events)