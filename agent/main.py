import process_monitor
import process_tree
from report_generator import create_report
from service_audit import audit_services
from suspicious_process import detect_suspicious_processes

print("========================================")
print("        WINDOWS MONITORING AGENT")
print("========================================")

print("\nStarting monitoring agent...")

print("\n[1] Service Audit")
audit_services()

print("\n[3] Parent-Child Process Monitoring")
process_tree.monitor_process_tree()

print("\n[4] Suspicious Process Detection")
events = detect_suspicious_processes()
create_report(events)
print("\n[2] Process Monitoring")
process_monitor.monitor_processes()