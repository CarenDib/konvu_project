import re
import requests
import difflib
import os
import openai
import json

CIRCL_CVE_API = "https://vulnerability.circl.lu/api/cve/{}"


def fetch_cve_circl(cve_id, timeout=10):
    url = CIRCL_CVE_API.format(cve_id)
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        else:
            return None
    except Exception as e:
        print(f"[fetch_cve_circl] HTTP error: {e}")
        return None


def keywords_from_circl(cve_json):
    keywords = set()
    if not cve_json:
        return keywords

    affected = cve_json.get("containers", {}).get("cna", {}).get("affected", [])
    for item in affected:
        vendor = item.get("vendor", "")
        product = item.get("product", "")
        for text in [vendor, product]:
            tokens = re.split(r'[:/,\s\.\-_]', text.lower())
            for t in tokens:
                if len(t) >= 3:
                    keywords.add(t)

    return keywords

def ai_adjustment_for_package(pkg, cve_json):
    """
    Calls OpenAI to suggest a score adjustment (-0.5 to +0.5) for a package based on the CVE info.
    """
    openai.api_key = os.getenv("OPENAI_API_KEY")
    if not openai.api_key:
        return 0.0, "No OpenAI API key set, skipping AI adjustment"

    prompt = f"""
You are a security analyst scoring whether a specific dependency from a local project is actually impacted by the given CVE.

Dependency under review:
- name: {pkg['name']}
- version: {pkg.get('version') or 'unknown'}
- ecosystem: {pkg.get('ecosystem')}

CVE (verbatim JSON excerpt):
{json.dumps(cve_json, indent=2)[:6000]}

Scoring rule (single number in [-0.5, 0.5]):
- +0.5..+0.3: strong evidence this dependency matches an affected product/version
- +0.3..+0.1: plausible relation but uncertain/partial version overlap
- 0: insufficient evidence either way
- -0.5..-0.1: clear evidence unrelated (different vendor/product/ecosystem)

Consider vendor/product names, known aliases, affected version ranges, and ecosystem alignment. Do NOT rely on generic descriptions alone.

Respond only in JSON: {{"adjustment": float, "reason": string}}
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant for software engineers. Always respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.0,
        )
        answer = response.choices[0].message.content.strip()
       
        data = json.loads(answer)
        
        adj = float(data.get("adjustment", 0.0))
        rsn = str(data.get("reason", "No reason provided"))

        adj = max(-0.5, min(0.5, adj))
        return adj, rsn

    except Exception as e:
        return 0.0, f"AI scoring failed: {e}"

def match_packages_to_cve(pkgs, cve_json, imports=None, use_llm_score=False):
    keywords = keywords_from_circl(cve_json)
    results = []
    for pkg in pkgs:
        name = pkg["name"].lower()
        score = 0.0
        reasons = []

        for k in keywords:
            if name in k or k in name:
                score = max(score, 0.8)
                reasons.append(f"keyword match: {k}")

        close = difflib.get_close_matches(name, list(keywords), n=1, cutoff=0.7)
        if close:
            score = max(score, 0.6)
            reasons.append(f"fuzzy close to {close[0]}")

        if score == 0.0 and cve_json and name in (cve_json.get("description") or "").lower():
            score = 0.5
            reasons.append("found in CVE description")

        if score > 0.0 and imports and name in imports:
            score = min(score + 0.2, 1.0)
            reasons.append("imported in project code (relevant)")

        if use_llm_score:
            adjustment, reason = ai_adjustment_for_package(pkg, cve_json)
            score = score + adjustment
            reasons.append(reason)

        results.append({
            "package": pkg,
            "score": score,
            "reasons": reasons
        })
    return results