import psutil


def is_suspicious_path(path):
    if not path:
        return False

    path = path.lower()

    suspicious_locations = [
        "\\temp\\",
        "\\appdata\\",
        "\\downloads\\",
        "\\users\\public\\"
    ]

    for location in suspicious_locations:
        if location in path:
            return True

    return False


def get_severity(path):
    if not path:
        return "UNKNOWN"

    path = path.lower()

    if "\\temp\\" in path or "\\downloads\\" in path:
        return "HIGH"

    if "\\appdata\\" in path or "\\users\\public\\" in path:
        return "MEDIUM"

    return "LOW"


def audit_services():
    print("===== WINDOWS SERVICE AUDIT =====")

    for service in psutil.win_service_iter():
        try:
            info = service.as_dict()

            name = info.get("name")
            display_name = info.get("display_name")
            status = info.get("status")
            start_type = info.get("start_type")
            binpath = info.get("binpath")

            print("\nService Name :", name)
            print("Display Name :", display_name)
            print("Status       :", status)
            print("Start Type   :", start_type)
            print("Binary Path  :", binpath)
            if not binpath:
                print("⚠️ ALERT: Service has no binary path!")
                print("Severity     : HIGH")
            if start_type == "automatic":
                print("Startup      : Service starts automatically")
                if start_type == "automatic" and is_suspicious_path(binpath):
                    print("⚠️ ALERT: Suspicious automatic service detected!")
                    print("Severity     :", get_severity(binpath))

            if is_suspicious_path(binpath):
                severity = get_severity(binpath)

                print("⚠️ ALERT: Suspicious service path detected!")
                print("Severity     :", severity)

        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    audit_services()