import re
from urllib.parse import urlparse

URGENT_TERMS = [
    "immediately", "urgent", "verify your account", "suspended", "unusual sign-in",
    "password expires", "act now", "within 24 hours", "confirm your password",
    "payment failed", "account will be closed"
]
CREDENTIAL_TERMS = ["password", "login", "log in", "credentials", "one-time passcode", "otp", "bank details"]
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

def extract_urls(text):
    return URL_RE.findall(text or "")

def analyze_email(email_data):
    sender = email_data.get("sender", "")
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    combined = f"{subject}\n{body}".lower()
    urls = extract_urls(combined)
    reasons = []
    score = 0

    urgent_hits = [term for term in URGENT_TERMS if term in combined]
    credential_hits = [term for term in CREDENTIAL_TERMS if term in combined]
    if urgent_hits:
        score += min(25, 10 + 5 * (len(urgent_hits) - 1))
        reasons.append("Urgency or account-pressure language: " + ", ".join(urgent_hits[:4]))
    if credential_hits:
        score += 15
        reasons.append("Message refers to passwords, login details or authentication codes.")

    if urls:
        score += min(30, 10 * len(urls))
        reasons.append(f"Contains {len(urls)} URL(s); inspect the destination and domain before opening.")
        for url in urls[:5]:
            host = (urlparse(url).hostname or "").lower()
            if host.startswith("xn--") or "@" in urlparse(url).netloc:
                score += 15
                reasons.append("URL contains a potentially deceptive hostname or user-info pattern.")
                break
            if host.endswith(".example") or host.endswith(".test") or host.endswith(".invalid"):
                reasons.append("URL uses a reserved testing domain; this is not evidence of a live malicious site.")

    if not sender:
        reasons.append("Sender field was not supplied, so sender identity could not be assessed.")
    elif "@" not in sender:
        score += 10
        reasons.append("Sender address does not look like a complete email address.")

    if len(body.strip()) < 30:
        reasons.append("Very little message body was available for analysis.")

    score = min(score, 100)
    if score >= 60:
        verdict, level = "Potential phishing", "High"
    elif score >= 30:
        verdict, level = "Suspicious — review required", "Medium"
    else:
        verdict, level = "No strong phishing indicators found", "Low"

    return {
        "score": score,
        "verdict": verdict,
        "level": level,
        "reasons": reasons or ["No obvious indicators were found by the starter rules."],
        "urls": urls,
        "note": "Starter heuristic only. It is not a trained AI model and cannot prove that an email is safe."
    }
