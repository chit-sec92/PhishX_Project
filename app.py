import streamlit as st
import json, base64, io, os
from src.phishx.analyzer import analyze_eml_bytes
from src.phishx.utils import to_text

st.set_page_config(page_title="PhishX — Phishing Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ PhishX — Phishing Email Analyzer")
st.caption("Upload a .eml file *or* paste raw headers/body. Get SPF/DKIM/DMARC, URL intel, whois, and a risk score.")

tab1, tab2 = st.tabs(["Upload .eml","Paste raw"])

data_bytes = None

with tab1:
    file = st.file_uploader("Choose a .eml file", type=["eml"])
    if file is not None:
        data_bytes = file.read()

with tab2:
    raw_headers = st.text_area("Headers (optional)", height=200,
                               placeholder="Paste raw email headers here...")
    raw_body = st.text_area("Body (HTML or text)", height=250,
                            placeholder="Paste the email body here...")
    if st.button("Analyze pasted content"):
        if raw_headers or raw_body:
            # Build minimal RFC822 message
            content = (raw_headers or "") + "\n\n" + (raw_body or "")
            data_bytes = content.encode("utf-8", "ignore")
        else:
            st.warning("Please paste headers or body.")

if data_bytes:
    with st.spinner("Analyzing..."):
        result = analyze_eml_bytes(data_bytes)

    left, right = st.columns([2,1])
    with right:
        st.metric("Risk Score (0-100)", result["risk"]["score"])
        st.progress(result["risk"]["score"]/100)

        if st.button("Download JSON report"):
            j = json.dumps(result, indent=2, ensure_ascii=False)
            b = j.encode("utf-8")
            st.download_button("Save report.json", b, file_name="phishx_report.json", mime="application/json")

    with left:
        st.subheader("Verdict & Reasons")
        for r in result["risk"]["reasons"]:
            st.write(f"- **{r['rule']}** (+{r['weight']}) — {r.get('evidence','')}")

        st.subheader("Headers")
        st.code(json.dumps(result["headers"], indent=2))

        st.subheader("URLs Found")
        if result["urls"]:
            for u in result["urls"]:
                st.write(u)
        else:
            st.write("No URLs found.")

        st.subheader("DNS & Auth")
        st.json(result["dns"])

        st.subheader("Whois (top domains)")
        st.json(result["whois"])

        if result.get("virustotal"):
            st.subheader("VirusTotal (first URL)")
            st.json(result["virustotal"])

        st.subheader("Body Preview (first 2KB)")
        st.code(result["body_preview"] or "(empty)")

st.markdown("---")
st.caption("Tip: Set `VT_API_KEY` in your environment to enable VirusTotal lookups for the first URL.")
