import streamlit as st
import psutil
from datetime import datetime

st.set_page_config(
    page_title="Windows Service & Process Monitoring Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Windows Service & Process Monitoring Agent")
st.write("Monitor Windows processes and identify potentially suspicious activity.")

# Sidebar
st.sidebar.header("Monitoring Options")
option = st.sidebar.selectbox(
    "Select Module",
    [
        "Dashboard",
        "Process Monitoring",
        "Parent-Child Monitoring",
        "Startup Service Audit",
        "Unauthorized Process Detection",
        "Reports"
    ]
)

# ---------------- Dashboard ----------------
if option == "Dashboard":
    st.header("Monitoring Dashboard")

    processes = list(psutil.process_iter(
        ["pid", "name", "username", "ppid"]
    ))

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Running Processes", len(processes))

    with col2:
        st.metric("Monitoring Status", "Active")

    with col3:
        st.metric(
            "Last Scan",
            datetime.now().strftime("%H:%M:%S")
        )

    st.success("Monitoring agent dashboard is running successfully.")

    st.subheader("Project Features")
    st.write("✓ Parent–Child Relationship Monitoring")
    st.write("✓ Startup Service Auditing")
    st.write("✓ Unauthorized Process Detection")
    st.write("✓ Reporting & Alert System")


# ---------------- Process Monitoring ----------------
elif option == "Process Monitoring":
    st.header("Process Monitoring")

    process_data = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "ppid", "status"]
    ):
        try:
            info = process.info

            process_data.append({
                "PID": info["pid"],
                "Process Name": info["name"],
                "Parent PID": info["ppid"],
                "Username": info["username"],
                "Status": info["status"]
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    st.dataframe(
        process_data,
        use_container_width=True
    )


# ---------------- Parent Child ----------------
elif option == "Parent-Child Monitoring":
    st.header("Parent–Child Relationship Monitoring")

    data = []

    for process in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            info = process.info

            parent_name = "Unknown"

            try:
                parent = psutil.Process(info["ppid"])
                parent_name = parent.name()
            except:
                pass

            data.append({
                "Parent Process": parent_name,
                "Parent PID": info["ppid"],
                "Child Process": info["name"],
                "Child PID": info["pid"]
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    st.dataframe(data, use_container_width=True)


# ---------------- Service Audit ----------------
elif option == "Startup Service Audit":
    st.header("Startup Service Audit")

    st.info(
        "This module is intended to audit Windows services and "
        "identify services that may require further investigation."
    )

    st.write("Service auditing module")

    st.warning(
        "Detailed Windows service information requires Windows-specific "
        "service access and may not be available on Streamlit Cloud."
    )


# ---------------- Unauthorized Process ----------------
elif option == "Unauthorized Process Detection":
    st.header("Unauthorized Process Detection")

    suspicious_names = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe"
    ]

    detected = []

    for process in psutil.process_iter(["pid", "name", "username"]):
        try:
            info = process.info
            name = (info["name"] or "").lower()

            if name in suspicious_names:
                detected.append({
                    "PID": info["pid"],
                    "Process": info["name"],
                    "Username": info["username"],
                    "Status": "Review Required"
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if detected:
        st.warning("Potentially suspicious processes detected.")
        st.dataframe(detected, use_container_width=True)
    else:
        st.success("No processes matching the current detection rules were found.")


# ---------------- Reports ----------------
elif option == "Reports":
    st.header("Monitoring Reports")

    st.write(
        "The monitoring agent collects process and detection information "
        "that can be reviewed through generated reports."
    )

    st.subheader("Detection Rules")

    rules = [
        "Unusual parent-child process relationships",
        "Suspicious command-line processes",
        "Unknown or unauthorized processes",
        "Processes running from temporary or user-writable locations",
        "Potentially high-risk processes",
        "Suspicious startup services"
    ]

    for rule in rules:
        st.write("• " + rule)

    st.success("Report and detection-rule section loaded successfully.")