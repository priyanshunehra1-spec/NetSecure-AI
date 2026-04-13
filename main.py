import streamlit as st
import pandas as pd
import joblib
import os
import glob
import base64
import datetime


# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="NetSecure AI",
    layout="wide",
    page_icon="🛡️"
)

# ---------------- THEME ----------------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #0b0b1f, #1a103d, #2d1b69);
    color: white;
}

/* Sticky Navbar */
.sticky-header {
    position: sticky;
    top: 0;
    z-index: 999;
    background: rgba(11, 11, 31, 0.95);
    backdrop-filter: blur(10px);
    padding: 10px 20px;
    border-radius: 0 0 18px 18px;
    box-shadow: 0 0 20px rgba(168,85,247,0.25);
}

div[role="radiogroup"] {
    display: flex;
    justify-content: flex-end;
    gap: 20px;
}

h1, h2, h3 {
    color: #c084fc !important;
}

.stButton>button {
    background: linear-gradient(90deg, #7c3aed, #a855f7);
    color: white;
    border-radius: 14px;
    font-weight: 700;
    border: none;
    box-shadow: 0 0 20px rgba(168,85,247,0.4);
    padding: 14px;
}

[data-testid="metric-container"] {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(192,132,252,0.15);
    border-radius: 18px;
    padding: 18px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION ----------------
if "started" not in st.session_state:
    st.session_state.started = False

if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- NAVBAR ----------------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #0b0b1f, #1a103d, #2d1b69);
    color: white;
}

/* Radio menu aligned right */
div[role="radiogroup"] {
    display: flex !important;
    justify-content: flex-end !important;
    align-items: center !important;
    gap: 10px;
    width: 100%;
    margin-top: 25px;
}

/* Hide radio circles */
div[role="radiogroup"] > label > div:first-child {
    display: none;
}

/* Menu text */
div[role="radiogroup"] label {
    color: white !important;
    font-size: 16px !important;
    font-weight: 600 !important;
}
</style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
left, right = st.columns([30, 20])

with left:
    st.markdown("""
    <h2 style='color:#c084fc; margin-top:8px;'>
    🛡️ NetSecure AI
    </h2>
    """, unsafe_allow_html=True)

with right:
    page = st.radio(
    "",
    ["Home", "Learn", "Batch Scan", "Download", "Developed By"],
    horizontal=True,
    label_visibility="collapsed"
    )

# ---------------- LOAD MODEL ----------------
model = joblib.load("rf.sav")
scaler = joblib.load("scaler.sav")
label_encoders = joblib.load("label_encoders.sav")

features = [
    'service', 'flag', 'src_bytes', 'dst_bytes', 'count',
    'same_srv_rate', 'diff_srv_rate', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_same_src_port_rate'
]

# ---------------- PREDICT ----------------
def predict_class(values):
    df = pd.DataFrame([dict(zip(features, values))])

    for col in ['service', 'flag']:
        df[col] = label_encoders[col].transform(df[col].astype(str))

    scaled = scaler.transform(df)
    pred = model.predict(scaled)
    prob = model.predict_proba(scaled)

    return pred[0], prob[0]

# ---------------- LANDING PAGE ----------------
def landing_page():
    st.markdown("""
    <div style='text-align:center; padding:70px 20px;'>
        <h1 style='font-size:64px; margin-bottom:10px;'>🛡️ NetSecure AI</h1>
        <p style='font-size:24px; color:#ddd6fe; margin-bottom:20px;'>
            Intelligent Network Intrusion Detection Platform
        </p>
        <p style='font-size:18px; max-width:850px; margin:auto; color:#cbd5e1; line-height:1.8;'>
            Detect cyber threats in real-time using machine learning.
            This system analyzes network traffic features and predicts
            whether the traffic is safe or malicious with enterprise-level intelligence.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # -------- CENTER METRICS --------
    left_space, c1, c2, c3, right_space = st.columns([1, 2, 2, 2, 1])

    with c1:
        st.metric("🎯 Accuracy", "91.7%")
    with c2:
        st.metric("⚡ Detection", "Real-Time")
    with c3:
        st.metric("🧠 Model", "Logistic Regression")

    # Space below metrics
    st.markdown("<div style='margin-top:40px;'></div>", unsafe_allow_html=True)

    # -------- CENTER BUTTON --------
    left, center, right = st.columns([3, 4, 3])

    with center:
        if st.button("🚀 Start AI Detection", use_container_width=True):
            st.session_state.started = True
            st.rerun()
# ---------------- HOME PAGE ----------------


def home_page():
    st.markdown("""
    <h1 style='text-align:center; font-size:52px;'>
    🛡️ AI Threat Intelligence Dashboard
    </h1>
    <p style='text-align:center; color:#ddd6fe; font-size:18px;'>
    Real-time cyber threat analysis
    </p>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("## 🌐 Connection Details")
        service = st.selectbox("Service", list(label_encoders['service'].classes_))
        flag = st.selectbox("Flag", list(label_encoders['flag'].classes_))
        src_bytes = st.number_input("Source Bytes", 0)
        dst_bytes = st.number_input("Destination Bytes", 0)
        count = st.number_input("Count", 1)
        dst_host_srv_count = st.number_input("Destination Host Service Count", 255)

    with c2:
        st.markdown("## 📊 Traffic Intelligence")
        same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, 1.0)
        diff_srv_rate = st.slider("Different Service Rate", 0.0, 1.0, 0.0)
        dst_host_same_srv_rate = st.slider("Destination Host Same Service Rate", 0.0, 1.0, 1.0)
        dst_host_same_src_port_rate = st.slider("Destination Host Same Source Port Rate", 0.0, 1.0, 0.0)

    if st.button("🚀 Run Threat Analysis", use_container_width=True):
        values = [
            service, flag, src_bytes, dst_bytes, count,
            same_srv_rate, diff_srv_rate,
            dst_host_srv_count, dst_host_same_srv_rate,
            dst_host_same_src_port_rate
        ]

        pred, prob = predict_class(values)

        anomaly_score = prob[0] * 100
        safe_score = prob[1] * 100

        if pred == 0:
            st.error(f"🚨 HIGH THREAT DETECTED | Risk Score: {anomaly_score:.2f}%")
        else:
            st.success(f"✅ TRAFFIC SAFE | Confidence: {safe_score:.2f}%")

        st.markdown("## 🎯 Threat Score Meter")
        st.progress(int(anomaly_score))

        m1, m2 = st.columns(2)
        with m1:
            st.metric("🚨 Threat Probability", f"{anomaly_score:.2f}%")
        with m2:
            st.metric("✅ Safe Probability", f"{safe_score:.2f}%")

        # ✅ Save to history
        st.session_state.history.append({
            "🕐 Time": datetime.datetime.now().strftime("%H:%M:%S"),
            "🌐 Service": service,
            "🚩 Flag": flag,
            "📤 Src Bytes": src_bytes,
            "📥 Dst Bytes": dst_bytes,
            "🔢 Count": count,
            "🚨 Threat %": f"{anomaly_score:.2f}%",
            "✅ Safe %": f"{safe_score:.2f}%",
            "🔍 Result": "🚨 Attack" if pred == 0 else "✅ Normal"
        })

    # ✅ Show History Table
    if st.session_state.history:
        st.markdown("---")
        st.markdown("## 🕐 Prediction History")
        df_history = pd.DataFrame(st.session_state.history)
        st.dataframe(df_history, use_container_width=True, hide_index=True)

        col1, col2, col3 = st.columns([3, 2, 3])
        with col2:
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.history = []
                st.rerun()

    st.markdown("<div style='margin-top:35px;'></div>", unsafe_allow_html=True)

    # 📘 Expandable Example Scenarios
    with st.expander("📘 Example Traffic Scenarios (Click to View)", expanded=False):
        ex1, ex2 = st.columns(2)

        with ex1:
            st.success("""
            ✅ **Normal Traffic Example**
            - Service: `http`
            - Flag: `SF`
            - Source Bytes: `200`
            - Destination Bytes: `5000`
            - Count: `5`
            - Same Service Rate: `1.0`
            - Different Service Rate: `0.0`
            - Destination Host Service Count: `255`
            - Destination Host Same Service Rate: `1.0`
            - Destination Host Same Source Port Rate: `0.0`

            **Why Normal?**
            - Low connection count ✅
            - High same service rate ✅
            - Stable destination host behavior ✅
            - Proper data transfer observed ✅
            """)

        with ex2:
            st.error("""
            🚨 **Attack Traffic Example**
            - Service: `private`
            - Flag: `S0`
            - Source Bytes: `0`
            - Destination Bytes: `0`
            - Count: `100`
            - Same Service Rate: `0.05`
            - Different Service Rate: `0.95`
            - Destination Host Service Count: `10`
            - Destination Host Same Service Rate: `0.1`
            - Destination Host Same Source Port Rate: `0.9`

            **Why Attack?**
            - High connection count 🚨
            - Same service rate very low 🚨
            - Different service rate too high 🚨
            - Zero byte transfer suspicious 🚨
            - Repeated same source port activity 🚨
            """)

        st.markdown("---")
        st.markdown("### 🧠 Quick Detection Logic")

        st.info("""
        🚨 **Likely Attack if:**
        - `Count` is very **high**
        - `Different Service Rate` is **high**
        - `Source/Destination Bytes` are **zero**
        - `Destination Host Same Source Port Rate` is **high**
        - `Same Service Rate` is **low**

        ✅ **Likely Normal if:**
        - `Count` is **low**
        - `Same Service Rate` is **high**
        - Stable byte transfer exists
        - Destination host behavior is consistent
        """)

    # 🔽 Bottom Back Button
    st.markdown("<br><br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([3, 4, 3])
    with col2:
        if st.button("⬅ Back", use_container_width=True):
            st.session_state.started = False
            st.rerun()

# ---------------- LEARN ----------------
def learn_page():
    st.title("📘 Learn About NetSecure AI")

    st.markdown("""
    ## 🔍 Project Overview
    **NetSecure AI** is an intelligent **Network Intrusion Detection System (NIDS)** 
    built using **Machine Learning (Logistic Regression)**.

    The goal of this project is to analyze network traffic parameters
    and automatically classify them into:

    - ✅ Normal Traffic
    - 🚨 Malicious / Intrusion Traffic

    This helps organizations proactively identify suspicious traffic
    and prevent cyber attacks.

    ---

    ## 🎯 Problem Statement
    Traditional security systems rely on rule-based detection methods,
    which often fail against modern unknown threats.

    Our system solves this by using **AI-based anomaly detection**
    to learn traffic behavior patterns and classify suspicious activity.

    ---

    ## 🧠 Machine Learning Model Used
    We used **Logistic Regression**, a supervised machine learning
    classification algorithm.

    It works by:
    1. Taking network traffic features as input
    2. Applying learned weights
    3. Using the sigmoid function
    4. Producing a probability score
    5. Classifying traffic as normal or attack

    ### Why Logistic Regression?
    - Fast and efficient
    - High interpretability
    - Best for binary classification
    - Works well on structured numerical data
    - Low computational cost

    ---

    ## ⚙️ Features Used
    The model uses **10 important traffic parameters**:

    - **service** → Type of network service
    - **flag** → Connection status
    - **src_bytes** → Bytes sent from source
    - **dst_bytes** → Bytes received by destination
    - **count** → Number of connections
    - **same_srv_rate** → Same service usage rate
    - **diff_srv_rate** → Different service rate
    - **dst_host_srv_count** → Destination host service count
    - **dst_host_same_srv_rate** → Same destination host service rate
    - **dst_host_same_src_port_rate** → Same source port usage rate

    These features collectively help identify suspicious patterns.

    ---

    ## 🔄 Workflow
    The project follows this pipeline:

    ### 1️⃣ Data Input
    User enters network traffic statistics using the dashboard.

    ### 2️⃣ Preprocessing
    - Categorical encoding
    - Numerical conversion
    - Missing value handling
    - Feature scaling

    ### 3️⃣ Model Prediction
    Logistic Regression predicts:
    - anomaly probability
    - normal probability

    ### 4️⃣ Threat Visualization
    Results are shown as:
    - 🚨 Threat detected
    - 🎯 Threat score meter
    - 📊 probability metrics

    ---

    ## 📊 Model Performance
    ### ✅ Accuracy: 91.7%
    The model provides strong detection performance
    for binary intrusion classification.

    Additional metrics:
    - High precision
    - Good recall
    - Low false positives
    - Fast inference speed

    ---

    ## 🌐 Real World Applications
    This project can be used in:

    - Enterprise SOC dashboards
    - Cloud infrastructure monitoring
    - Banking security systems
    - Firewall intelligence layers
    - Real-time traffic inspection

    ---

    ## 🚀 Future Scope
    Future enhancements include:

    - Live packet capture integration
    - Wireshark support
    - SIEM integration
    - Deep learning models
    - Cloud deployment
    - Real-time alert notifications

    ---

    ## 🛡️ Conclusion
    NetSecure AI demonstrates how machine learning can be applied
    to modern cybersecurity problems.

    It provides:
    - fast threat detection
    - intelligent anomaly scoring
    - scalable deployment potential
    - enterprise-ready dashboard interface
    """)

# ---------------- DOWNLOAD ----------------
from fpdf import FPDF
import io

# ---------------- DOWNLOAD ----------------
def download_page():
    st.title("⬇️ Download")
    st.markdown("### 📦 Available Downloads")

    col1, col2 = st.columns(2)

    # -------- PDF REPORT --------
    with col1:
        st.markdown("""
        <div style='background:rgba(255,255,255,0.05); border:1px solid rgba(192,132,252,0.3);
        border-radius:18px; padding:20px; text-align:center;'>
            <h3>📄 Project Report</h3>
            <p style='color:#ddd6fe;'>Full NetSecure AI summary including model info, features, and performance metrics.</p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        def generate_pdf():
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 20)
            pdf.cell(0, 12, "NetSecure AI - Project Report", ln=True, align="C")
            pdf.ln(5)

            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Project Overview", ln=True)
            pdf.set_font("Arial", size=11)
            pdf.multi_cell(0, 8, "NetSecure AI is an intelligent Network Intrusion Detection System (NIDS) built using Machine Learning (Logistic Regression). It classifies network traffic as Normal or Malicious in real-time.")
            pdf.ln(3)

            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Model Performance", ln=True)
            pdf.set_font("Arial", size=11)
            pdf.cell(0, 8, "Accuracy: 91.7%", ln=True)
            pdf.cell(0, 8, "Model: Logistic Regression", ln=True)
            pdf.cell(0, 8, "Detection: Real-Time", ln=True)
            pdf.cell(0, 8, "False Positives: Low", ln=True)
            pdf.ln(3)

            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Features Used", ln=True)
            pdf.set_font("Arial", size=11)
            features_list = [
                "service - Type of network service",
                "flag - Connection status",
                "src_bytes - Bytes sent from source",
                "dst_bytes - Bytes received by destination",
                "count - Number of connections",
                "same_srv_rate - Same service usage rate",
                "diff_srv_rate - Different service rate",
                "dst_host_srv_count - Destination host service count",
                "dst_host_same_srv_rate - Same destination host service rate",
                "dst_host_same_src_port_rate - Same source port usage rate"
            ]
            for f in features_list:
                pdf.cell(0, 8, f"  - {f}", ln=True)
            pdf.ln(3)

            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Developed By", ln=True)
            pdf.set_font("Arial", size=11)
            pdf.cell(0, 8, "Guide: Dr. A Swaminathan", ln=True)
            pdf.cell(0, 8, "Developers: Priyanshu & Kaviraj", ln=True)

            return bytes(pdf.output(dest='S').encode('latin-1'))

        pdf_bytes = generate_pdf()
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_bytes,
            file_name="NetSecureAI_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    # -------- CSV SAMPLE DATA --------
    with col2:
        st.markdown("""
        <div style='background:rgba(255,255,255,0.05); border:1px solid rgba(192,132,252,0.3);
        border-radius:18px; padding:20px; text-align:center;'>
            <h3>📊 Sample Traffic Data</h3>
            <p style='color:#ddd6fe;'>Example network traffic records with both normal and attack samples for testing.</p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        def generate_csv():
            sample_data = {
                'service':      ['http', 'http', 'private', 'private', 'ftp', 'smtp'],
                'flag':         ['SF', 'SF', 'S0', 'S0', 'SF', 'SF'],
                'src_bytes':    [200, 500, 0, 0, 1000, 300],
                'dst_bytes':    [5000, 3000, 0, 0, 2000, 800],
                'count':        [5, 8, 100, 200, 3, 6],
                'same_srv_rate':[1.0, 0.9, 0.05, 0.02, 1.0, 1.0],
                'diff_srv_rate':[0.0, 0.1, 0.95, 0.98, 0.0, 0.0],
                'dst_host_srv_count': [255, 255, 10, 5, 255, 255],
                'dst_host_same_srv_rate': [1.0, 1.0, 0.1, 0.05, 1.0, 1.0],
                'dst_host_same_src_port_rate': [0.0, 0.1, 0.9, 0.95, 0.0, 0.0],
                'label': ['Normal', 'Normal', 'Attack', 'Attack', 'Normal', 'Normal']
            }
            df = pd.DataFrame(sample_data)
            return df.to_csv(index=False).encode('utf-8')

        csv_bytes = generate_csv()
        st.download_button(
            label="📊 Download Sample CSV",
            data=csv_bytes,
            file_name="NetSecureAI_SampleData.csv",
            mime="text/csv",
            use_container_width=True
        )

# ---------------- DEVELOPED BY ----------------
def developed_page():
    st.markdown("""
    <div style='text-align:center; padding:30px;'>
        <h1>👨‍💻 Developed By</h1>
        <p style='color:#ddd6fe;'>Meet the team behind NetSecure AI</p>
    </div>
    """, unsafe_allow_html=True)

    def get_image_base64(name):
        files = glob.glob(f"{name}.*")
        if not files:
            return None
        with open(files[0], "rb") as f:
            return base64.b64encode(f.read()).decode()

    guide_img = get_image_base64("guide")
    priyanshu_img = get_image_base64("priyanshu")
    kaviraj_img = get_image_base64("kaviraj")

    # ---------------- MENTOR ----------------
    st.markdown(f"""
    <div style="text-align:center; margin-bottom:40px;">
        <img src="data:image/png;base64,{guide_img}"
             style="width:180px; height:180px; border-radius:50%;
                    object-fit:cover; border:4px solid #a855f7;">
        <h2 style="margin-top:15px; color:#c084fc;">Dr. A Swaminathan</h2>
        <p style="color:white;">Project Guide & Mentor</p>
    </div>
    """, unsafe_allow_html=True)

    # ---------------- TEAM ----------------
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"""
        <div style="text-align:center;">
            <img src="data:image/png;base64,{priyanshu_img}"
                 style="width:160px; height:160px; border-radius:50%;
                        object-fit:cover; border:3px solid #7c3aed;">
            <h3 style="margin-top:15px; color:#c084fc;">Priyanshu</h3>
            <p style="color:white;">AI Security Developer</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div style="text-align:center;">
            <img src="data:image/png;base64,{kaviraj_img}"
                 style="width:160px; height:160px; border-radius:50%;
                        object-fit:cover; border:3px solid #7c3aed;">
            <h3 style="margin-top:15px; color:#c084fc;">Kaviraj</h3>
            <p style="color:white;">AI Security Developer</p>
        </div>
        """, unsafe_allow_html=True)
        
# ---------------- BATCH SCAN ----------------
def batch_scan_page():
    st.markdown("""
    <h1 style='text-align:center; font-size:48px;'>
    📂 Batch Traffic Scanner
    </h1>
    <p style='text-align:center; color:#ddd6fe; font-size:18px;'>
    Upload a CSV file to scan multiple traffic records at once
    </p>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # -------- INSTRUCTIONS --------
    with st.expander("📋 How to use Batch Scanner", expanded=False):
        st.info("""
        **Your CSV must have these exact columns:**
        - `service` → e.g. http, ftp, smtp
        - `flag` → e.g. SF, S0, REJ
        - `src_bytes` → number
        - `dst_bytes` → number
        - `count` → number
        - `same_srv_rate` → 0.0 to 1.0
        - `diff_srv_rate` → 0.0 to 1.0
        - `dst_host_srv_count` → number
        - `dst_host_same_srv_rate` → 0.0 to 1.0
        - `dst_host_same_src_port_rate` → 0.0 to 1.0

        💡 You can download a sample CSV from the **Download** page!
        """)

    # -------- FILE UPLOAD --------
    uploaded_file = st.file_uploader(
        "📁 Upload your CSV file",
        type=["csv"],
        help="CSV must contain the required traffic feature columns"
    )

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ File uploaded successfully! Found **{len(df)} records**.")

            # Show preview
            st.markdown("### 👀 Data Preview")
            st.dataframe(df.head(5), use_container_width=True, hide_index=True)

            # Check required columns
            required_cols = [
                'service', 'flag', 'src_bytes', 'dst_bytes', 'count',
                'same_srv_rate', 'diff_srv_rate', 'dst_host_srv_count',
                'dst_host_same_srv_rate', 'dst_host_same_src_port_rate'
            ]
            missing = [c for c in required_cols if c not in df.columns]

            if missing:
                st.error(f"🚨 Missing columns: {', '.join(missing)}")
                return

            # -------- RUN BATCH PREDICTION --------
            if st.button("🚀 Run Batch Analysis", use_container_width=True):
                with st.spinner("🔍 Analyzing all records..."):

                    results = []
                    for _, row in df.iterrows():
                        values = [
                            row['service'], row['flag'],
                            row['src_bytes'], row['dst_bytes'], row['count'],
                            row['same_srv_rate'], row['diff_srv_rate'],
                            row['dst_host_srv_count'], row['dst_host_same_srv_rate'],
                            row['dst_host_same_src_port_rate']
                        ]
                        try:
                            pred, prob = predict_class(values)
                            anomaly_score = prob[0] * 100
                            safe_score = prob[1] * 100
                            result = "🚨 Attack" if pred == 0 else "✅ Normal"
                        except:
                            anomaly_score = 0
                            safe_score = 0
                            result = "⚠️ Error"

                        results.append({
                            "🌐 Service": row['service'],
                            "🚩 Flag": row['flag'],
                            "📤 Src Bytes": row['src_bytes'],
                            "📥 Dst Bytes": row['dst_bytes'],
                            "🔢 Count": row['count'],
                            "🚨 Threat %": f"{anomaly_score:.2f}%",
                            "✅ Safe %": f"{safe_score:.2f}%",
                            "🔍 Result": result
                        })

                    result_df = pd.DataFrame(results)

                    # -------- SUMMARY --------
                    total = len(result_df)
                    attacks = sum(1 for r in results if r["🔍 Result"] == "🚨 Attack")
                    normal = total - attacks

                    st.markdown("---")
                    st.markdown("## 📊 Scan Summary")

                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.metric("📋 Total Scanned", total)
                    with m2:
                        st.metric("🚨 Threats Found", attacks)
                    with m3:
                        st.metric("✅ Normal Traffic", normal)

                    # -------- RESULTS TABLE --------
                    st.markdown("## 🔍 Detailed Results")
                    st.dataframe(result_df, use_container_width=True, hide_index=True)

                    # -------- DOWNLOAD RESULTS --------
                    st.markdown("### ⬇️ Download Results")
                    csv_out = result_df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="📥 Download Results as CSV",
                        data=csv_out,
                        file_name="NetSecureAI_BatchResults.csv",
                        mime="text/csv",
                        use_container_width=True
                    )

        except Exception as e:
            st.error(f"🚨 Error reading file: {e}")
            
# ---------------- ROUTER ----------------
if page == "Home":
    if not st.session_state.started:
        landing_page()
    else:
        home_page()

elif page == "Learn":
    learn_page()

elif page == "Download":
    download_page()

elif page == "Developed By":
    developed_page()

elif page == "Batch Scan":
    batch_scan_page()