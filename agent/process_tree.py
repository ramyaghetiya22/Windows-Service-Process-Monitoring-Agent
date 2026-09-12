import psutil


def monitor_process_tree():

    print("\n========================================")
    print("       PARENT-CHILD PROCESS TREE")
    print("========================================")

    processes = {}

    
    for process in psutil.process_iter(['pid', 'ppid', 'name']):
        try:
            processes[process.info['pid']] = {
                'name': process.info['name'],
                'ppid': process.info['ppid']
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    print("\nProcess Relationships:")
    print("----------------------")

    
    for pid, info in processes.items():

        parent_pid = info['ppid']
        process_name = info['name']

        if parent_pid in processes:

            parent_name = processes[parent_pid]['name']

            print(
                parent_name,
                f"(PID: {parent_pid})",
                "→",
                process_name,
                f"(PID: {pid})"
            )