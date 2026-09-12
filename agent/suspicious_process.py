import psutil
import os


def load_list(filename):

    file_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "config",
        filename
    )

    try:
        with open(file_path, "r") as file:
            return [line.strip().lower() for line in file if line.strip()]
    except FileNotFoundError:
        return []


def detect_suspicious_processes():

    print("\n========================================")
    print("     SUSPICIOUS PROCESS DETECTION")
    print("========================================")

    whitelist = load_list("whitelist.txt")
    blacklist = load_list("blacklist.txt")

    suspicious_relationships = {
        "winword.exe": ["cmd.exe", "powershell.exe"],
        "excel.exe": ["cmd.exe", "powershell.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe"]
    }

    processes = {}

    for process in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):

        try:
            pid = process.info['pid']
            ppid = process.info['ppid']
            name = process.info['name']
            path = process.info['exe']

            if name:

                processes[pid] = {
                    'ppid': ppid,
                    'name': name.lower(),
                    'path': path
                }

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    found = False
    events = []

    print("\nChecking Unauthorized Processes...")
    print("----------------------------------------")

    for pid, info in processes.items():

        name = info['name']

        # Blacklist check
        if name in blacklist:

            print("\n🔴 BLACKLISTED PROCESS DETECTED")
            print("Process :", name)
            print("PID     :", pid)
            print("Path    :", info['path'])
            print("Severity: HIGH")
            events.append(f"Blacklisted process: {name} | PID: {pid} | Path: {info['path']} | Severity: HIGH")

            found = True

        # Whitelist check
        elif name not in whitelist:

            print("\n⚠️ UNKNOWN PROCESS DETECTED")
            print("Process :", name)
            print("PID     :", pid)
            print("Path    :", info['path'])
            print("Severity: MEDIUM")
            events.append(f"Unknown process: {name} | PID: {pid} | Path: {info['path']} | Severity: MEDIUM")
            found = True

    print("\nChecking Suspicious Parent-Child Relationships...")
    print("----------------------------------------")

    for pid, info in processes.items():

        parent_pid = info['ppid']
        child_name = info['name']

        if parent_pid in processes:

            parent_name = processes[parent_pid]['name']

            if (
                parent_name in suspicious_relationships
                and child_name in suspicious_relationships[parent_name]
            ):

                print("\n⚠️ SUSPICIOUS RELATIONSHIP DETECTED")
                print("Parent :", parent_name)
                print("Child  :", child_name)
                print("Parent PID :", parent_pid)
                print("Child PID  :", pid)
                print("Severity: HIGH")
                events.append(f"Suspicious relationship: {parent_name} -> {child_name} | Parent PID: {parent_pid} | Child PID: {pid} | Severity: HIGH")

                found = True
    if not found:
        print("\n✅ No suspicious processes detected.")
    return events


if __name__ == "__main__":
    detect_suspicious_processes()