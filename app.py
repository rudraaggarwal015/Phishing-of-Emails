import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from email import policy
from email.parser import BytesParser
from detector import analyze_email

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-development-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"eml", "txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_eml(data):
    msg = BytesParser(policy=policy.default).parsebytes(data)
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "text" and part.get_content_disposition() != "attachment":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append("")
    return {
        "sender": str(msg.get("From", "")),
        "subject": str(msg.get("Subject", "")),
        "body": "\n".join(str(x) for x in body_parts),
        "headers": {k: str(v) for k, v in msg.items()}
    }

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    mode = request.form.get("mode", "text")
    if mode == "upload":
        file = request.files.get("email_file")
        if not file or not file.filename:
            flash("Choose an .eml or .txt file first.")
            return redirect(url_for("index"))
        if not allowed_file(file.filename):
            flash("Only .eml and .txt files are supported.")
            return redirect(url_for("index"))
        raw = file.read()
        if file.filename.lower().endswith(".eml"):
            email_data = parse_eml(raw)
        else:
            email_data = {"sender": "", "subject": "", "body": raw.decode("utf-8", errors="replace"), "headers": {}}
    else:
        email_data = {
            "sender": request.form.get("sender", ""),
            "subject": request.form.get("subject", ""),
            "body": request.form.get("body", ""),
            "headers": {}
        }
    result = analyze_email(email_data)
    return render_template("result.html", result=result, email_data=email_data)

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(debug=True)
