import psutil
import time
from datetime import datetime


def get_process_snapshot():
    processes = {}

    for process in psutil.process_iter(
        ['pid', 'ppid', 'name', 'exe', 'status', 'create_time']
    ):
        try:
            info = process.info

            processes[info['pid']] = {
                'pid': info['pid'],
                'ppid': info['ppid'],
                'name': info['name'],
                'path': info['exe'],
                'status': info['status'],
                'start_time': datetime.fromtimestamp(
                    info['create_time']
                ).strftime("%Y-%m-%d %H:%M:%S")
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return processes


def monitor_processes():
    print("========================================")
    print("       WINDOWS PROCESS MONITOR")
    print("========================================")

    previous_processes = get_process_snapshot()

    print(f"Monitoring started...")
    print(f"Initial processes found: {len(previous_processes)}")

    while True:
        time.sleep(3)

        current_processes = get_process_snapshot()

        new_processes = set(current_processes) - set(previous_processes)
        terminated_processes = set(previous_processes) - set(current_processes)

        for pid in new_processes:
            process = current_processes[pid]

            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] NEW PROCESS DETECTED")
            print("Name:", process['name'])
            print("PID:", process['pid'])
            print("Parent PID:", process['ppid'])
            print("Path:", process['path'])

        for pid in terminated_processes:
            process = previous_processes[pid]

            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] PROCESS TERMINATED")
            print("Name:", process['name'])
            print("PID:", process['pid'])

        previous_processes = current_processes