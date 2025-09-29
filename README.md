# Konvu Project — CVE Impact Scanner

A lightweight CLI tool to help software and security engineers quickly assess whether a specific CVE (Common Vulnerability and Exposure) is likely relevant to a local codebase.

It fetches CVE details, scans your repository for declared dependencies and actual Python imports, then produces a concise report highlighting potential matches and risk levels. Optionally, it can generate a plain‑English explanation of the CVE with an LLM.

## Features
- Scan dependency manifests across ecosystems:
  - Python: `requirements.txt`, `Pipfile`, `pyproject.toml`
  - JavaScript/TypeScript: `package.json`
  - Go: `go.mod`
  - Java: `pom.xml`
- Inspect actual Python imports in your repository to gauge real usage
- Fetch CVE details from CIRCL (`vulnerability.circl.lu`)
- Score and list packages potentially affected by the CVE
- Generate a readable report with risk hints
- Optional LLM explanation of the CVE (OpenAI)

## Installation
1. Clone this repository and navigate to the project directory.
2. (Recommended) Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start
From the project root, run:

```bash
python project.py CVE-2021-44228 --path .
```

- `CVE-2021-44228` is an example; replace with the CVE you want to analyze.
- `--path` points to the repository you want to scan (defaults to current directory).

Example output includes:
- The CVE identifier, title, and description
- Detected packages and their risk score
- Short recommendations

## Optional: LLM Explanation
If you want a plain‑English summary of the CVE impact, enable the LLM explainer:

```bash
python project.py CVE-2021-44228 --use-llm
```

Set your OpenAI API key first. You can define it in a `.env` file in the project root:

```
OPENAI_API_KEY=sk-...
```

or export it in your shell environment before running the command.

## How It Works
- Fetch CVE JSON from CIRCL
- Extract keyword candidates (vendor, product) from CVE data
- Parse dependency manifests to build a package list
- Scan Python files to collect actually imported libraries
- Heuristically score each package against CVE keywords and usage
- Render a human‑readable report

## Rationale Behind Our Choices
-Focused on lightweight heuristics to quickly highlight potential risks without exhaustive static analysis.
-Scoring combines keyword relevance and actual usage, prioritizing packages that are both present in the code and affected by the CVE.
-CIRCL chosen as primary CVE source due to structured JSON output and reliability.
-Modular design: parsing, scanning, and reporting are decoupled for easy extension.

## How/Where We Used AI Tools
-ChatGPT: Used during development to clarify problem-solving approaches, design heuristics, and ensure correct methodology.
-Cursor.ai: Assisted with code auto-completion and boilerplate generation, speeding up implementation.

## Future Work
-Extend import scanning to other languages (JS/TS, Go, Java) to improve coverage.
-Enhance heuristics with a “LLM thinking score”: analyze CVE relevance using AI reasoning on dependency context and code usage.
-Incorporate transitive dependency analysis to detect indirect vulnerability exposure.
-Refine scoring with weighted factors combining declared dependencies, actual imports, and AI insights.

## Commands and Options
```bash
python project.py <CVE_ID> [--path <repo_dir>] [--use-llm]
```

- `<CVE_ID>`: Required, e.g., `CVE-2023-12345`
- `--path`: Directory of the repository to scan (default: `.`)
- `--use-llm`: Adds an AI explanation to the end of the report

## Limitations
- Matching is heuristic and best‑effort; always verify with vendor advisories
- Only Python files are inspected for imports
- Some manifest formats are parsed partially and may miss edge cases

## Development
Key modules:
- `project.py`: CLI entry point and orchestration
- `deps_utils.py`: Manifest discovery and parsing
- `imports_scan.py`: AST‑based Python import extraction
- `cve_utils.py`: CIRCL fetch and package‑to‑CVE matching
- `report_utils.py`: Report rendering and optional LLM explanation
