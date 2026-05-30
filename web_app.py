import streamlit as st
from detector import PhishingDetector
from screenshot import capture_screenshot
from PIL import Image

st.set_page_config(page_title='Phishing Website Detector', layout='centered')

# Custom dark UI
st.markdown("""
    <style>
        .stApp {
            background: linear-gradient(to right, #1c1c1c, #2b2b2b);
            color: white;
        }
        .main-title {
            font-size: 40px;
            text-align: center;
            color: #00ffe1;
            font-weight: bold;
            margin-bottom: 30px;
        }
        .section {
            background-color: #2e2e2e;
            padding: 20px;
            margin-top: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }
        .section-title {
            font-size: 22px;
            color: #ffffff;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .stTextInput>div>div>input {
            background-color: #1e1e1e;
            color: white;
            border: 1px solid #555;
            border-radius: 5px;
            padding: 8px;
        }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🚨 Phishing Website Detector</div>', unsafe_allow_html=True)

# URL input
st.markdown('<div class="section">', unsafe_allow_html=True)
st.markdown('<div class="section-title">🔗 Enter a Website URL</div>', unsafe_allow_html=True)
url = st.text_input('', placeholder='https://example.com')
st.markdown('</div>', unsafe_allow_html=True)

# Analyze
if st.button("🔍 Analyze Website"):
    if url:
        detector = PhishingDetector(url)
        result = detector.detect_phishing()
        legit_site = detector.get_legitimate_site()

        st.markdown('<div class="section">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🧪 Detection Result</div>', unsafe_allow_html=True)
        if "Phishing" in result:
            st.error(f"🚫 {result}")
            if legit_site:
                st.markdown(f"✅ **Did you mean?** [Go to the legitimate site]({legit_site})")
        elif "Warning" in result:
            st.warning(f"⚠️ {result}")
        else:
            st.success(f"✅ {result}")
        st.markdown('</div>', unsafe_allow_html=True)

        # Screenshot
        st.markdown('<div class="section">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🌐 Website Screenshot</div>', unsafe_allow_html=True)
        image_path = capture_screenshot(url)
        if image_path:
            image = Image.open(image_path)
            st.image(image, caption="Website Preview", use_container_width=True)
        else:
            st.warning("⚠️ Could not capture screenshot.")
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning("Please enter a valid URL.")
