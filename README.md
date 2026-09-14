# 🛡️ Email Threat Forensics — IIT Quantum Cryptography Edition

A high-performance forensic email security platform featuring real-time BEC (Business Email Compromise) detection, header trace path analysis, identity correlation, PDF report export, and a **state-of-the-art IIT Quantum Cryptography live visual background engine**.

---

## ✨ Features

- **🔍 Full Email Parsing & Forensic Tracing**: Extracts IP hops, SPF/DKIM/DMARC authentication trails, return-path anomalies, and sender domain intelligence.
- **⚡ BEC & Fraud Detection**: Machine-learning backed threat scoring engine assessing spoofing indicators, tampered headers, and suspicious links.
- **🌐 Geolocation & Origin Mapping**: Interactive Leaflet map pinpointing the estimated physical origin of the email.
- **📊 Attributable Campaigns**: Automated grouping of correlated cases sharing sender domains, IPs, or threat infrastructure.
- **📄 Forensic PDF Exports**: Chain-of-custody compliant audit reports generated on-demand.
- **🌌 IIT Quantum Cryptography Theme**: Breathtaking HTML5 Canvas 2D engine featuring cascading SHA-256 streams, rotating optical reticles, interactive decryption lenses, and glassmorphic HUD interfaces.

---

## 🛠️ Tech Stack

- **Backend**: Python 3, Flask, SQLite3, ReportLab, Scikit-Learn
- **Frontend**: HTML5, Vanilla CSS3 (Glassmorphism), JavaScript (Canvas 2D API), Leaflet.js
- **Deployment**: Gunicorn WSGI, Ready for Render / Railway / Heroku / Vercel

---

## 🚀 Quick Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/email-forensics.git
   cd email-forensics
   ```

2. **Create a virtual environment & install dependencies**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate

   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app/server.py
   ```

4. **Open in browser**:
   Navigate to `http://127.0.0.1:5000`

---

## 🌐 Deploy Live

### Deploy on Render (Recommended - Free)

1. Push your repository to GitHub.
2. Sign up on [Render.com](https://render.com/).
3. Click **New +** -> **Web Service**.
4. Connect your GitHub repository `email-forensics`.
5. Configure settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --chdir app server:app`
6. Click **Create Web Service**. Your app is live! 🎉

---

## 📝 License

Distributed under the MIT License.
