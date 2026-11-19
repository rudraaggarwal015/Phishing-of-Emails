# MailGuard — Email Phishing Detection Starter

A defensive educational prototype for scanning pasted email text and `.eml` / `.txt` files. It includes a read-only Gmail API starter script.

## Important limitations

- The web scanner currently uses transparent heuristic rules, **not a trained AI model**.
- The Gmail connector currently checks headers and subject only. It does not yet decode and analyze full message bodies or attachments.
- Gmail integration is optional and requires your own Google Cloud OAuth credentials.
- It never sends, deletes, or modifies Gmail messages.
- A low score does not prove an email is safe. Do not automatically block messages based only on this prototype.

## 1. Requirements

- Python 3.10 or newer
- VS Code (recommended)
- A browser
- Internet connection to install Python packages

## 2. Setup

### Windows PowerShell

```powershell
cd phishing_detection_complete_starter
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

If PowerShell blocks activation, use Command Prompt:

```cmd
venv\\Scripts\\activate.bat
```

Then open `http://127.0.0.1:5000`.

### macOS / Linux

```bash
cd phishing_detection_complete_starter
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

## 3. Test the scanner

- Paste a sample email into the form, or upload an `.eml` file.
- Use the harmless sample file created for this project: `github_phishing_awareness_sample.eml`.
- Review the score, reasons and extracted URLs.
- The sample is designed for training. Its `.example` URL is reserved and is not a real malicious site.

## 4. Enable Gmail read-only scanning

1. Open Google Cloud Console: https://console.cloud.google.com/
2. Create a project and enable **Gmail API**.
3. Configure the OAuth consent screen for your test account.
4. Create an OAuth Client ID of type **Desktop app**.
5. Download the client JSON and save it in this project folder as `credentials.json`.
6. Keep `credentials.json` private. It is excluded by `.gitignore`.
7. With the virtual environment active, run:

```bash
python gmail_scan.py
```

8. Complete Google's sign-in and consent flow. The script requests `gmail.readonly`.
9. It scans up to 10 messages from the last 7 days and prints a basic assessment.

For a production-quality Gmail feature, implement MIME body decoding, pagination, safe URL extraction, robust error handling, consent/privacy controls and a user interface. Never request broader Gmail permissions unless a feature truly requires them.

## 5. Suggested development roadmap

1. Improve MIME parsing and extract plain-text / HTML bodies safely.
2. Add URL feature extraction and reputation lookups using trusted services.
3. Prepare a labelled dataset and train a baseline TF-IDF + Logistic Regression model.
4. Evaluate precision, recall, F1-score, false-positive rate and false-negative rate.
5. Add a database for scan history and audit events.
6. Add Gmail OAuth per user, with read-only access first.
7. Add safe attachment scanning through an isolated sandbox; never execute attachments on the web server.
8. Add user feedback and a review workflow before considering quarantine automation.

## 6. GitHub safety

Before publishing:
- Never commit `.env`, `credentials.json`, `token.json`, real emails or personal data.
- Use synthetic or properly anonymized datasets.
- Rotate any credential accidentally committed.
- Do not publish OAuth tokens or API keys.

## Project structure

```text
phishing_detection_complete_starter/
├── app.py
├── detector.py
├── gmail_scan.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── templates/
│   ├── index.html
│   └── result.html
└── static/
    └── style.css
```
