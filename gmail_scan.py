"""
Read-only Gmail scanner.
1) Enable Gmail API in Google Cloud.
2) Create an OAuth Desktop app credential and save it as credentials.json.
3) Run: python gmail_scan.py
The script requests gmail.readonly only. It does not send, delete, or modify email.
"""
import os
from email import message_from_bytes, policy
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from detector import analyze_email

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = os.getenv("GOOGLE_TOKEN_FILE", "token.json")
CREDENTIALS_FILE = os.getenv("GOOGLE_CLIENT_SECRET_FILE", "credentials.json")

def get_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w", encoding="utf-8") as token:
            token.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def get_header(headers, name):
    for item in headers or []:
        if item.get("name", "").lower() == name.lower():
            return item.get("value", "")
    return ""

def main():
    service = get_service()
    response = service.users().messages().list(userId="me", q="in:anywhere newer_than:7d", maxResults=10).execute()
    messages = response.get("messages", [])
    if not messages:
        print("No messages found in the selected search window.")
        return
    for item in messages:
        msg = service.users().messages().get(userId="me", id=item["id"], format="full").execute()
        payload = msg.get("payload", {})
        headers = payload.get("headers", [])
        sender = get_header(headers, "From")
        subject = get_header(headers, "Subject")
        # Gmail API payload body is not decoded in this minimal starter.
        # Header-only scan is deliberately conservative; use the web upload scanner for full .eml analysis.
        data = {"sender": sender, "subject": subject, "body": "", "headers": headers}
        result = analyze_email(data)
        print("=" * 72)
        print("From:", sender)
        print("Subject:", subject)
        print("Risk:", result["level"], "| Score:", result["score"])
        print("Verdict:", result["verdict"])
        print("Note: this starter Gmail connector currently analyzes headers/subject only.")

if __name__ == "__main__":
    main()
