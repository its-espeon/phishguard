import os
import tldextract
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

from utils.url_analyzer import analyze_url, get_domain_age, calculate_heuristic_score
from utils.api_clients import check_virustotal

load_dotenv()

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Prepend https:// if no scheme given
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # --- Heuristic Analysis ---
    findings = analyze_url(url)

    # --- Domain Age ---
    extracted = tldextract.extract(url)
    registered_domain = extracted.registered_domain or extracted.domain
    domain_age = get_domain_age(registered_domain)

    # --- Heuristic Score ---
    heuristic_score, flags = calculate_heuristic_score(findings, domain_age)

    # --- VirusTotal API ---
    vt_result = check_virustotal(url)

    # --- Final Reputation Score ---
    # Blend heuristic (60%) and VirusTotal (40%) scores
    vt_score = 0
    if vt_result.get("positives") is not None and vt_result.get("total", 0) > 0:
        vt_ratio = vt_result["positives"] / vt_result["total"]
        vt_score = int(vt_ratio * 100)

    if vt_result.get("positives") is not None:
        final_score = int((heuristic_score * 0.6) + (vt_score * 0.4))
    else:
        final_score = heuristic_score

    final_score = min(final_score, 100)

    # Determine verdict
    if final_score >= 70:
        verdict = "Dangerous"
        verdict_class = "dangerous"
    elif final_score >= 40:
        verdict = "Suspicious"
        verdict_class = "suspicious"
    elif final_score >= 15:
        verdict = "Caution"
        verdict_class = "caution"
    else:
        verdict = "Safe"
        verdict_class = "safe"

    return jsonify({
        "url": url,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "final_score": final_score,
        "heuristic_score": heuristic_score,
        "flags": flags,
        "findings": findings,
        "domain_age": domain_age,
        "virustotal": vt_result,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
