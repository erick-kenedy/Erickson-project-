import streamlit as st
import pandas as pd

from scanner.network import scan_host
from scanner.scan import scan_directory
from scanner.risk import score
from scanner.report import generate_csv, report_header


st.set_page_config(
    page_title="NetGuard",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ NetGuard")
st.subheader("Network & Data Security Assessment Platform")

st.warning(
    "Use this application only on systems, networks and data "
    "that you own or are explicitly authorized to assess."
)


network_tab, data_tab, dashboard_tab = st.tabs(
    [
        "🌐 Network Scanner",
        "🔐 Data Scanner",
        "📊 Security Dashboard",
    ]
)


if "network_findings" not in st.session_state:
    st.session_state.network_findings = []

if "data_findings" not in st.session_state:
    st.session_state.data_findings = []


# ---------------------------------------------------------
# NETWORK SCANNER
# ---------------------------------------------------------

with network_tab:

    st.header("Network Vulnerability Assessment")

    target = st.text_input(
        "Target hostname or IP address",
        value="127.0.0.1"
    )

    ports_text = st.text_input(
        "TCP ports",
        value=(
            "21,22,23,25,53,80,110,139,"
            "143,443,445,3306,3389,5432,8080"
        )
    )

    timeout = st.slider(
        "Connection timeout",
        min_value=0.1,
        max_value=3.0,
        value=0.5,
        step=0.1
    )

    if st.button(
        "🔎 Start Network Assessment",
        type="primary"
    ):

        try:

            ports = [
                int(port.strip())
                for port in ports_text.split(",")
                if port.strip()
            ]

            if not ports:
                raise ValueError(
                    "Enter at least one port."
                )

            if any(
                port < 1 or port > 65535
                for port in ports
            ):
                raise ValueError(
                    "Ports must be between 1 and 65535."
                )

            with st.spinner(
                "Assessing network connection..."
            ):

                findings = scan_host(
                    target,
                    ports,
                    timeout
                )

            st.session_state.network_findings = findings

            total, level = score(findings)

            st.success(
                f"Assessment complete — Risk: {level}"
            )

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Open services",
                len(findings)
            )

            col2.metric(
                "Risk score",
                total
            )

            col3.metric(
                "Overall risk",
                level
            )

            if not findings:

                st.success(
                    "No selected TCP ports accepted connections."
                )

            for finding in findings:

                with st.container():

                    st.markdown(
                        f"### Port {finding['port']} — "
                        f"{finding['service']}"
                    )

                    st.write(
                        f"**Risk:** {finding['risk']}"
                    )

                    st.write(
                        f"**Finding:** {finding['finding']}"
                    )

                    st.info(
                        f"Recommended action: "
                        f"{finding['action']}"
                    )


# ---------------------------------------------------------
# DATA SCANNER
# ---------------------------------------------------------

with data_tab:

    st.header("Data Security Assessment")

    directory = st.text_input(
        "Directory to assess",
        value="."
    )

    max_files = st.number_input(
        "Maximum files",
        min_value=10,
        max_value=10000,
        value=1000,
        step=100
    )

    if st.button(
        "🔎 Start Data Assessment",
        type="primary"
    ):

        try:

            with st.spinner(
                "Checking files..."
            ):

                findings = scan_directory(
                    directory,
                    int(max_files)
                )

            st.session_state.data_findings = findings

            total, level = score(findings)

            st.success(
                f"Assessment complete — Risk: {level}"
            )

            col1, col2 = st.columns(2)

            col1.metric(
                "Findings",
                len(findings)
            )

            col2.metric(
                "Risk score",
                total
            )

            for finding in findings:

                with st.container():

                    st.markdown(
                        f"### {finding['type']}"
                    )

                    st.write(
                        f"**Risk:** {finding['risk']}"
                    )

                    st.code(
                        finding["path"]
                    )

                    st.write(
                        finding["finding"]
                    )

                    st.info(
                        f"Recommended action: "
                        f"{finding['action']}"
                    )

        except Exception as error:

            st.error(
                f"Assessment failed: {error}"
            )


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

with dashboard_tab:

    st.header("Security Dashboard")

    all_findings = (
        st.session_state.network_findings
        + st.session_state.data_findings
    )

    total, level = score(all_findings)

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Total findings",
        len(all_findings)
    )

    c2.metric(
        "Risk score",
        total
    )

    c3.metric(
        "Overall risk",
        level
    )

    if all_findings:

        rows = []

        for finding in all_findings:

            rows.append({
                "Risk": finding.get("risk", "Info"),
                "Type": (
                    finding.get("type")
                    or finding.get("service")
                    or "Network finding"
                ),
                "Location": (
                    finding.get("path")
                    or f"Port {finding.get('port', '')}"
                ),
                "Recommendation": finding.get(
                    "action",
                    ""
                )
            })

        dataframe = pd.DataFrame(rows)

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True
        )

        csv_data = generate_csv(
            all_findings
        )

        st.download_button(
            "⬇️ Export CSV Report",
            csv_data,
            "netguard-security-report.csv",
            "text/csv"
        )

        text_report = (
            report_header("Current assessment")
            + "\n".join(
                [
                    f"{f.get('risk')} | "
                    f"{f.get('type') or f.get('service')} | "
                    f"{f.get('finding')} | "
                    f"Action: {f.get('action')}"
                    for f in all_findings
                ]
            )
        )

        st.download_button(
            "⬇️ Export Text Report",
            text_report,
            "netguard-security-report.txt",
            "text/plain"
        )

    else:

        st.success(
            "No assessment findings are currently loaded."
        )


st.divider()

st.caption(
    "NetGuard v1.0 — Defensive security assessment tool. "
    "Use only with authorization."
)
