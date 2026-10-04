import os
import base64
import time
import requests

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


def _parse_attributes(attributes: dict) -> dict:
    """Extract and return standardised fields from a VT URL attributes block."""
    stats = attributes.get("last_analysis_stats", {}) or attributes.get("stats", {})
    results = attributes.get("last_analysis_results", {}) or attributes.get("results", {})

    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values())

    flagged_by = [
        engine for engine, detail in results.items()
        if detail.get("category") in ("malicious", "suspicious")
    ]

    # Friendly scan date
    scan_date = attributes.get("last_analysis_date") or attributes.get("date")

    return {
        "positives": positives,
        "total": total,
        "scan_date": scan_date,
        "stats": stats,
        "flagged_by": flagged_by[:10],
        "error": None
    }


def check_virustotal(url: str) -> dict:
    """
    Looks up a URL on VirusTotal using the v3 API.

    Strategy:
      1. Try to fetch a cached report via the URL identifier (base64url of the URL).
      2. If no cached report exists (404), submit the URL for a fresh scan,
         wait briefly, and then poll the analysis result up to 3 times.
    """
    _empty = {"positives": None, "total": None, "scan_date": None,
              "stats": {}, "flagged_by": [], "error": None}

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        return {**_empty, "error": "VirusTotal API key not configured."}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # ── Step 1: Try the cached URL report ──────────────────────────────────
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        cached_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if cached_resp.status_code == 200:
            attributes = cached_resp.json().get("data", {}).get("attributes", {})
            parsed = _parse_attributes(attributes)
            # Only use the cached report if it actually has engine data
            if parsed["total"] > 0:
                return parsed

        # 404 or empty cached result → fall through to fresh scan
    except requests.exceptions.Timeout:
        return {**_empty, "error": "VirusTotal request timed out."}
    except requests.exceptions.HTTPError as e:
        if e.response.status_code not in (404, 400):
            return {**_empty, "error": f"VirusTotal HTTP error: {e.response.status_code}"}
    except Exception as e:
        return {**_empty, "error": str(e)}

    # ── Step 2: Submit URL for a fresh scan ────────────────────────────────
    try:
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json().get("data", {}).get("id", "")

        if not analysis_id:
            return {**_empty, "error": "Could not submit URL to VirusTotal."}

    except requests.exceptions.Timeout:
        return {**_empty, "error": "VirusTotal submission timed out."}
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return {**_empty, "error": "Invalid VirusTotal API key."}
        if e.response.status_code == 429:
            return {**_empty, "error": "VirusTotal rate limit exceeded. Try again in a minute."}
        return {**_empty, "error": f"VirusTotal HTTP error: {e.response.status_code}"}
    except Exception as e:
        return {**_empty, "error": str(e)}

    # ── Step 3: Poll analysis result (up to 3 attempts, 5 s apart) ─────────
    for attempt in range(3):
        try:
            time.sleep(5)  # Give VT time to complete the scan
            analysis_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )
            analysis_resp.raise_for_status()
            data = analysis_resp.json()

            attributes = data.get("data", {}).get("attributes", {})
            status = attributes.get("status", "")

            if status in ("completed", ""):
                parsed = _parse_attributes(attributes)
                if parsed["total"] > 0:
                    return parsed
                # Status is completed but total is still 0 on first attempt — retry once more

        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.HTTPError:
            continue
        except Exception as e:
            return {**_empty, "error": str(e)}

    # ── Step 4: Fall back to the cached URL report one more time ───────────
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        fallback = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        if fallback.status_code == 200:
            attributes = fallback.json().get("data", {}).get("attributes", {})
            return _parse_attributes(attributes)
    except Exception:
        pass

    return {**_empty, "error": "VirusTotal scan is still in progress. Try again in a moment."}
