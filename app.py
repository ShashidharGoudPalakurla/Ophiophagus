import streamlit as st
import streamlit_authenticator as stauth
import yaml
import pandas as pd
import plotly.express as px
from yaml.loader import SafeLoader
from backend_engine import OphiophagusExpertEngine

st.set_page_config(page_title="Ophiophagus AI Pentester Console", layout="wide", page_icon="🐍")

if "log_history" not in st.session_state:
    st.session_state.log_history = []

if "authentication_status" not in st.session_state:
    st.session_state["authentication_status"] = None

# --- Configuration Parsing Engine ---
try:
    with open('config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)
except FileNotFoundError:
    st.error("System Error: Critical configuration file `config.yaml` is missing.")
    st.stop()

authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days']
)

authenticator.login(location='main')

if st.session_state["authentication_status"] == False:
    st.error('Authentication Error: Invalid operator credentials provided.')
elif st.session_state["authentication_status"] == None:
    st.info('🔑 Operational Security Lock: Please log in to initialize the framework.')
elif st.session_state["authentication_status"]:
    
    name = st.session_state["name"]
    
    # --- Navigation Sidebar Component ---
    st.sidebar.title("🐍 Ophiophagus Engine")
    st.sidebar.markdown(f"**Operator Account:** `{name}`")
    app_mode = st.sidebar.radio("Console Navigation", ["Scanner Dashboard", "Session Audit Logs"])
    st.sidebar.markdown("---")
    authenticator.logout('Terminate Console Session', 'sidebar')
    
    # Initialize Core Security Script Engine
    engine = OphiophagusExpertEngine()

    # ================= PANEL ONE: SCANNER DASHBOARD =================
    if app_mode == "Scanner Dashboard":
        st.title("🎯 Professional Vulnerability Assessment Workspace")
        st.markdown("Execute socket scans, cryptography checks, and header reviews to analyze actual asset vulnerabilities and attack risks.")
        
        target_input = st.text_input("Provide Application Target URL or Host IP Asset Address:", placeholder="192.168.1.1 or example.com")
        
        if st.button("Launch Pentest Sequence", type="primary"):
            if target_input.strip():
                with st.spinner(f"Ophiophagus engine actively executing script matrices on {target_input}..."):
                    
                    # Run multi-tier assessment scripts
                    scan_results = engine.execute_advanced_assessment(target_input)
                    st.session_state.log_history.append(scan_results)
                    
                    findings_list = scan_results["findings"]
                    df = pd.DataFrame(findings_list)
                    
                    st.success(f"Dynamic assessment completed for host: {scan_results['resolved_ip']}")
                    
                    # --- Data Analytics Display Charts ---
                    st.subheader("📊 Threat Modeling & Risk Composition Dashboard")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        fig_pie = px.pie(
                            df, names='severity', title='Vulnerability Density by Severity Level',
                            color='severity',
                            color_discrete_map={
                                'Critical': '#b30000', 'High': '#e65c00', 
                                'Medium': '#e6b800', 'Low': '#2db300', 'None': '#4f5d75'
                            }
                        )
                        st.plotly_chart(fig_pie, use_container_width=True)
                        
                    with col2:
                        fig_bar = px.bar(
                            df, x='title', y='cvss', title='CVSS Vector Threat Weight Comparison',
                            labels={'cvss': 'Calculated CVSS Impact Metric', 'title': 'Detected System Risk Factor'},
                            color='cvss', color_continuous_scale=px.colors.sequential.Oranges
                        )
                        st.plotly_chart(fig_bar, use_container_width=True)
                    
                    # --- Targeted Vulnerability and Cyber Attack Vector Reporting Map ---
                    st.subheader("📑 Targeted Vulnerability Assessment Findings & Remediation Code")
                    
                    for finding in findings_list:
                        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "None": "⚪"}.get(finding['severity'], "⚠️")
                        expander_title = f"{icon} {finding['title']} — Severity: {finding['severity']} [CVSS: {finding['cvss']}]"
                        
                        with st.expander(expander_title):
                            # Explicit Mapping to the Cyber Attack Vector
                            st.error(f"☠️ **Leads to Cyber Attack:** {finding['attack_vector']}")
                            st.markdown(f"**Vulnerability Context:**\n{finding['description']}")
                            st.markdown(f"**Remediation Steps:**\n{finding['remediation']}")
                            st.markdown("**Remediation Implementation Code (Secure Configuration Example):**")
                            st.code(finding['secure_code'], language='python')
            else:
                st.error("Operational Fault: Target reference parameters cannot be left blank.")

    # ================= PANEL TWO: AUDIT LOG RETRIEVAL =================
    elif app_mode == "Session Audit Logs":
        st.title("🗄️ Run Log Registry Database")
        st.markdown("Historical audit summaries compiled during this application lifecycle instance.")
        
        if not st.session_state.log_history:
            st.info("No active operations recorded during this platform deployment runtime session context.")
        else:
            for idx, log in enumerate(reversed(st.session_state.log_history)):
                actual_id = len(st.session_state.log_history) - idx
                st.markdown(f"### Assessment Record #{actual_id}")
                
                c1, c2, c3 = st.columns(3)
                c1.metric("Target Anchor Link", str(log["target"]))
                c2.metric("Mapped Network IP Node", str(log["resolved_ip"]))
                c3.metric("Timestamp Signature", str(log["timestamp"]))
                
                summaries = [f"{v['title']} -> Leads to: {v['attack_vector']}" for v in log["findings"]]
                st.markdown("**Identified Threat Mappings:**")
                for entry in summaries:
                    st.markdown(f"* {entry}")
                st.markdown("---")
