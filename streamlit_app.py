import streamlit as st
import pandas as pd

from scanner.network import scan_host
from scanner.scan import scan_directory
from scanner.risk import score
from scanner.report import (
    generate_csv,
    generate_json,
    generate_html,
    generate_text,
)
from services.ai_service import ask_ai


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="NetGuard Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------

DEFAULT_STATE = {
    "network_findings": [],
    "data_findings": [],
    "network_target": "",
    "data_directory": "",
    "ai_result": "",
}

for key, value in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def parse_ports(ports_text: str) -> list[int]:
    """Convert comma-separated port input into validated ports."""

    if not ports_text.strip():
        raise ValueError("Enter at least one TCP port.")

    ports = []

    for item in ports_text.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError(
                f"Invalid port: '{item}'. Ports must be numbers."
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Port {port} is outside the valid range 1-65535."
            )

        ports.append(port)

    if not ports:
        raise ValueError("Enter at least one valid TCP port.")

    return list(dict.fromkeys(ports))


def get_all_findings() -> list[dict]:
    """Return all findings currently stored in the session."""

    return (
        st.session_state.network_findings
        + st.session_state.data_findings
    )


def finding_type(finding: dict) -> str:
    """Return a readable finding type."""

    return (
        finding.get("type")
        or finding.get("service")
        or "Network finding"
    )


def finding_location(finding: dict) -> str:
    """Return a readable finding location."""

    if finding.get("path"):
        return str(finding["path"])

    if finding.get("port") is not None:
        return f"Port {finding['port']}"

    if finding.get("target"):
        return str(finding["target"])

    return "Unknown"


def render_finding(finding: dict) -> None:
    """Display one security finding."""

    risk = finding.get("risk", "Info")
    title = finding_type(finding)

    with st.container(border=True):
        st.subheader(title)

        col1, col2 = st.columns(2)

        with col1:
            st.write(f"**Risk:** {risk}")

        with col2:
            st.write(
                f"**Location:** {finding_location(finding)}"
            )

        if finding.get("finding"):
            st.write(
                f"**Finding:** {finding['finding']}"
            )

        if finding.get("action"):
            st.info(
                f"**Recommended action:** "
                f"{finding['action']}"
            )


def render_metrics(findings: list[dict]) -> None:
    """Display common security metrics."""

    total, level = score(findings)

    critical = sum(
        1
        for finding in findings
        if finding.get("risk") == "Critical"
    )

    high = sum(
        1
        for finding in findings
        if finding.get("risk") == "High"
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Total findings",
        len(findings),
    )

    c2.metric(
        "Risk score",
        total,
    )

    c3.metric(
        "Overall risk",
        level,
    )

    c4.metric(
        "High / Critical",
        critical + high,
    )


def build_dataframe(findings: list[dict]) -> pd.DataFrame:
    """Convert findings into a dashboard table."""

    rows = []

    for finding in findings:
        rows.append(
            {
                "Risk": finding.get("risk", "Info"),
                "Type": finding_type(finding),
                "Location": finding_location(finding),
                "Finding": finding.get("finding", ""),
                "Recommendation": finding.get(
                    "action",
                    "",
                ),
            }
        )

    return pd.DataFrame(rows)


def render_reports(findings: list[dict]) -> None:
    """Render report download buttons."""

    if not findings:
        return

    st.subheader("📄 Security Reports")

    csv_data = generate_csv(findings)
    json_data = generate_json(findings)
    text_data = generate_text(findings)
    html_data = generate_html(findings)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="⬇️ Download CSV",
            data=csv_data,
            file_name="netguard-security-report.csv",
            mime="text/csv",
            use_container_width=True,
        )

        st.download_button(
            label="⬇️ Download JSON",
            data=json_data,
            file_name="netguard-security-report.json",
            mime="application/json",
            use_container_width=True,
        )

    with col2:
        st.download_button(
            label="⬇️ Download Text",
            data=text_data,
            file_name="netguard-security-report.txt",
            mime="text/plain",
            use_container_width=True,
        )

        st.download_button(
            label="⬇️ Download HTML",
            data=html_data,
            file_name="netguard-security-report.html",
            mime="text/html",
            use_container_width=True,
        )


def render_ai_assistant(findings: list[dict]) -> None:
    """Render the AI security assistant."""

    if not findings:
        return

    st.divider()

    st.subheader("🤖 AI Security Assistant")

    st.write(
        "Get a simple defensive explanation of the "
        "current security findings and recommended "
        "priorities."
    )

    if st.button(
        "🤖 Explain Findings with AI",
        type="primary",
        use_container_width=True,
    ):
        with st.spinner(
            "AI is analyzing the security findings..."
        ):
            st.session_state.ai_result = ask_ai(
                findings
            )

    if st.session_state.ai_result:
        st.markdown("### 🧠 AI Assessment")
        st.info(st.session_state.ai_result)


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ NetGuard")

st.markdown(
    """
    ### Network & Data Security Assessment Platform

    Assess systems and files that you own or are explicitly
    authorized to test.
    """
)

st.warning(
    "⚠️ Authorization required: only assess systems, "
    "networks, and data that you own or have permission "
    "to assess."
)


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

with st.sidebar:
    st.header("🛡️ NetGuard")

    st.caption("Security Assessment Platform")

    st.divider()

    st.subheader("Current Session")

    all_findings = get_all_findings()

    st.metric(
        "Findings",
        len(all_findings),
    )

    total, level = score(all_findings)

    st.metric(
        "Risk Score",
        total,
    )

    st.metric(
        "Risk Level",
        level,
    )

    st.divider()

    if st.button(
        "🗑️ Clear Assessment",
        use_container_width=True,
    ):
        st.session_state.network_findings = []
        st.session_state.data_findings = []
        st.session_state.network_target = ""
        st.session_state.data_directory = ""
        st.session_state.ai_result = ""

        st.rerun()

    st.divider()

    st.caption(
        "NetGuard v1.2\n"
        "Defensive security assessment tool"
    )


# ---------------------------------------------------------
# MAIN NAVIGATION
# ---------------------------------------------------------

network_tab, data_tab, dashboard_tab = st.tabs(
    [
        "🌐 Network Scanner",
        "🔐 Data Scanner",
        "📊 Security Dashboard",
    ]
)


# =========================================================
# NETWORK SCANNER
# =========================================================

with network_tab:

    st.header("🌐 Network Security Assessment")

    st.write(
        "Check selected TCP ports on an authorized "
        "hostname or IP address."
    )

    with st.form("network_scan_form"):

        target = st.text_input(
            "Target hostname or IP address",
            value=(
                st.session_state.network_target
                or "127.0.0.1"
            ),
            help=(
                "Use a hostname or IP address belonging "
                "to a system you are authorized to assess."
            ),
        )

        ports_text = st.text_input(
            "TCP ports",
            value=(
                "21,22,23,25,53,80,110,139,"
                "143,443,445,3306,3389,5432,8080"
            ),
            help="Enter ports separated by commas.",
        )

        timeout = st.slider(
            "Connection timeout",
            min_value=0.1,
            max_value=3.0,
            value=0.5,
            step=0.1,
        )

        network_submit = st.form_submit_button(
            "🔎 Start Network Assessment",
            type="primary",
            use_container_width=True,
        )

    if network_submit:

        try:
            if not target.strip():
                raise ValueError(
                    "Enter a hostname or IP address."
                )

            ports = parse_ports(ports_text)

            st.session_state.network_target = (
                target.strip()
            )

            st.session_state.ai_result = ""

            with st.spinner(
                "Assessing selected TCP ports..."
            ):
                findings = scan_host(
                    target.strip(),
                    ports,
                    timeout,
                )

            st.session_state.network_findings = findings

            total, level = score(findings)

            st.success(
                f"Assessment complete — Overall risk: {level}"
            )

            render_metrics(findings)

            st.divider()

            if not findings:
                st.success(
                    "No selected TCP ports accepted "
                    "connections."
                )
            else:
                st.subheader(
                    f"Findings ({len(findings)})"
                )

                for finding in findings:
                    render_finding(finding)

                render_ai_assistant(findings)

        except ValueError as error:
            st.error(str(error))

        except Exception as error:
            st.error(
                "The network assessment could not be completed."
            )

            st.caption(
                f"Technical detail: {error}"
            )


# =========================================================
# DATA SCANNER
# =========================================================

with data_tab:

    st.header("🔐 Data Security Assessment")

    st.write(
        "Check an authorized local directory for "
        "potentially sensitive files or security findings."
    )

    with st.form("data_scan_form"):

        directory = st.text_input(
            "Directory to assess",
            value=(
                st.session_state.data_directory
                or "."
            ),
            help=(
                "Use a directory that you own or "
                "are authorized to assess."
            ),
        )

        max_files = st.number_input(
            "Maximum files",
            min_value=10,
            max_value=10000,
            value=1000,
            step=100,
        )

        data_submit = st.form_submit_button(
            "🔎 Start Data Assessment",
            type="primary",
            use_container_width=True,
        )

    if data_submit:

        try:
            if not directory.strip():
                raise ValueError(
                    "Enter a directory to assess."
                )

            st.session_state.data_directory = (
                directory.strip()
            )

            st.session_state.ai_result = ""

            with st.spinner(
                "Checking authorized files..."
            ):
                findings = scan_directory(
                    directory.strip(),
                    int(max_files),
                )

            st.session_state.data_findings = findings

            total, level = score(findings)

            st.success(
                f"Assessment complete — Overall risk: {level}"
            )

            render_metrics(findings)

            st.divider()

            if not findings:
                st.success(
                    "No security findings were detected."
                )
            else:
                st.subheader(
                    f"Findings ({len(findings)})"
                )

                for finding in findings:
                    render_finding(finding)

                render_ai_assistant(findings)

        except ValueError as error:
            st.error(str(error))

        except Exception as error:
            st.error(
                "The data assessment could not be completed."
            )

            st.caption(
                f"Technical detail: {error}"
            )


# =========================================================
# SECURITY DASHBOARD
# =========================================================

with dashboard_tab:

    st.header("📊 Security Dashboard")

    all_findings = get_all_findings()

    if not all_findings:

        st.info(
            "No assessment results are loaded yet. "
            "Run a Network or Data Assessment first."
        )

        st.markdown(
            """
            **Getting started**

            1. Open **Network Scanner** or **Data Scanner**.
            2. Enter an authorized target.
            3. Start the assessment.
            4. Return here to review the combined results.
            """
        )

    else:

        render_metrics(all_findings)

        st.divider()

        # -------------------------------------------------
        # RISK SUMMARY
        # -------------------------------------------------

        st.subheader("📈 Risk Summary")

        risk_counts = (
            pd.Series(
                [
                    finding.get("risk", "Info")
                    for finding in all_findings
                ]
            )
            .value_counts()
            .rename_axis("Risk")
            .reset_index(name="Count")
        )

        if not risk_counts.empty:
            st.bar_chart(
                risk_counts.set_index("Risk")
            )

        # -------------------------------------------------
        # FINDINGS TABLE
        # -------------------------------------------------

        st.subheader("🔎 All Findings")

        dataframe = build_dataframe(
            all_findings
        )

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

        # -------------------------------------------------
        # AI ASSISTANT
        # -------------------------------------------------

        render_ai_assistant(all_findings)

        # -------------------------------------------------
        # REPORTS
        # -------------------------------------------------

        st.divider()

        render_reports(all_findings)


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.divider()

st.caption(
    "NetGuard v1.2 — Defensive security assessment tool. "
    "Use only on systems, networks, and data you are "
    "authorized to assess."
)