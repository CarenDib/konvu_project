import os
import argparse
from pathlib import Path
from dotenv import load_dotenv

from deps_utils import extract_dependencies
from imports_scan import scan_project_imports
from cve_utils import fetch_cve_circl, match_packages_to_cve
from report_utils import generate_report, explain_cve_with_llm

load_dotenv()


def main():
    p = argparse.ArgumentParser(description="CVE explainer: fetch + local repo relevance scan")
    p.add_argument("cve", help="CVE identifier (e.g. CVE-2021-44228)")
    p.add_argument("--path", default=".", help="Path to repo (default current dir)")
    p.add_argument("--use-llm", action="store_true", help="Generate an AI explanation of the CVE")
    p.add_argument("--use-llm-score", action="store_true", help="Use LLM to score the packages")
    args = p.parse_args()

    root = Path(args.path).resolve()
    print(f"[+] scanning repo: {root}")

    # fetch CVE
    cve_json = fetch_cve_circl(args.cve)
    if not cve_json:
        print(f"[!] Unable to retrieve CVE details for {args.cve}")
        return
    
    print(f"[+] CVE fetched: {cve_json.get('cveMetadata', {}).get('cveId', {}) or args.cve}")

    # scan project dependencies
    pkgs, files = extract_dependencies(root)
    print(f"[+] found {len(files)} dependency manifest(s), {len(pkgs)} package references")

    # scan imports
    imports = scan_project_imports(root)
    print(f"[+] found {len(imports)} libraries actually imported in code")

    # match CVE - packages
    matches = match_packages_to_cve(pkgs, cve_json, imports, args.use_llm_score)
    report = generate_report(cve_json, matches)
    print("\n" + report)

    # optional: AI explanation
    if args.use_llm:
        print("\n=== AI Explanation (via LLM) ===\n")
        explanation = explain_cve_with_llm(cve_json)
        print(explanation)


if __name__ == "__main__":
    main()
