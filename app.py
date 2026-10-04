import streamlit as st

from url_analyzer import extract_features
from rules import calculate_risk


# -----------------------------
# Page Configuration
# -----------------------------

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔐",
    layout="wide"
)


# -----------------------------
# Title
# -----------------------------

st.title("🔐 Phishing URL Detection System")

st.write(
    "A rule-based cybersecurity tool that analyzes URLs "
    "and identifies potentially suspicious or phishing URLs."
)


# -----------------------------
# URL Input
# -----------------------------

url = st.text_input(
    "Enter URL",
    placeholder="Example: https://example.com/login"
)


# -----------------------------
# Analyze Button
# -----------------------------

if st.button("🔍 Analyze URL"):

    if not url.strip():

        st.warning("Please enter a URL.")

    else:

        # Extract features
        features = extract_features(url)

        # Calculate risk
        classification, score, reasons = calculate_risk(features)


        # -----------------------------
        # Result
        # -----------------------------

        st.divider()

        st.subheader("Detection Result")


        if classification == "PHISHING":

            st.error("🔴 PHISHING")

        elif classification == "SUSPICIOUS":

            st.warning("🟡 SUSPICIOUS")

        else:

            st.success("🟢 LEGITIMATE")


        st.metric(
            "Risk Score",
            f"{score}"
        )


        # -----------------------------
        # Reasons
        # -----------------------------

        st.subheader("🚨 Detection Reasons")

        if reasons:

            for reason in reasons:

                st.write("•", reason)

        else:

            st.write(
                "No significant suspicious indicators detected."
            )


        # -----------------------------
        # Features
        # -----------------------------

        st.subheader("🔎 Extracted URL Features")


        col1, col2, col3 = st.columns(3)


        with col1:

            st.write("**URL Length:**", features["url_length"])

            st.write(
                "**HTTPS:**",
                "Yes" if features["https"] else "No"
            )

            st.write(
                "**IP Address:**",
                "Yes" if features["has_ip"] else "No"
            )

            st.write(
                "**Shortened URL:**",
                "Yes" if features["is_shortened"] else "No"
            )


        with col2:

            st.write(
                "**Domain:**",
                features["domain"]
            )

            st.write(
                "**Subdomain:**",
                features["subdomain"] or "None"
            )

            st.write(
                "**Dots:**",
                features["dot_count"]
            )

            st.write(
                "**Hyphens:**",
                features["hyphen_count"]
            )


        with col3:

            st.write(
                "**Special Characters:**",
                features["special_character_count"]
            )

            st.write(
                "**Digits:**",
                features["digit_count"]
            )

            st.write(
                "**@ Symbol:**",
                "Yes" if features["has_at_symbol"] else "No"
            )

            st.write(
                "**Keywords:**",
                ", ".join(features["suspicious_keywords"])
                if features["suspicious_keywords"]
                else "None"
            )