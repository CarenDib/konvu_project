import json
import os
import openai

def generate_report(cve_json, matches, osv_lookup_results=None):
    lines = []
    cve_id = cve_json.get("cveMetadata", {}).get("cveId", {}) if cve_json else "UNKNOWN"
    lines.append(f"CVE: {cve_id}")
    if cve_json:
        lines.append(f"Title: {cve_json.get('containers', {}).get('cna', {}).get('title', {})}")
        lines.append(f"Description: {cve_json.get('containers', {}).get('cna', {}).get('descriptions', {})}")


    lines.append("\n=> Detected in the code (matches best-effort):")

    for m in matches:
        pkg = m["package"]
        score = m["score"]
        risk = "⚪ None"
        if score >= 0.8:
            if any("imported in project code" in r for r in m["reasons"]):
                risk = "🔴 High"
            else:
                risk = "🟡 Medium"
        elif score > 0:
            risk = "🟡 Medium"

        lines.append(f" - {pkg['name']} {pkg.get('version') or ''} "
                     f"(source: {pkg.get('source')}) score={score:.2f} risk={risk}")
        if m["reasons"]:
            for r in m["reasons"]:
                lines.append(f"    * {r}")

        if osv_lookup_results and pkg['name'] in osv_lookup_results:
            osvr = osv_lookup_results[pkg['name']]
            lines.append(f"    OSV result: {json.dumps(osvr, indent=2)[:300]} ...")

    lines.append("\nRecommendations (automatic; verify manually):")
    if any("🔴 High" in (line or "") for line in lines):
        lines.append(" - 🔴 High risk dependency: update/patch immediately.")
    elif any("🟡 Medium" in (line or "") for line in lines):
        lines.append(" - 🟡 Medium risk dependency: review version, check vendor advisory.")
    else:
        lines.append(" - No matching dependency found in scanned files.")

    return "\n".join(lines)


def explain_cve_with_llm(cve_json):
    openai.api_key = os.getenv("OPENAI_API_KEY")
    prompt = f"Explain this CVE to a software engineer in simple words:\n\n{json.dumps(cve_json, indent=2)}"

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant for software engineers."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"[OpenAI API error] {e}"
