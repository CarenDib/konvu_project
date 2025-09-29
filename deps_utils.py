import re
import json
from pathlib import Path
import xml.etree.ElementTree as ET

# Optional TOML loader
try:
    import tomllib as toml_lib  # Python 3.11+
except Exception:
    try:
        import toml as toml_lib  # Fallback to third-party
    except Exception:
        toml_lib = None


def find_manifest_files(root: Path):
    candidates = []
    for p in root.rglob("*"):
        name = p.name.lower()
        if name in ("requirements.txt", "pipfile", "pyproject.toml", "package.json", "go.mod", "pom.xml"):
            candidates.append(p)
    return candidates


def parse_requirements_txt(path: Path):
    out = []
    with open(path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*([=<>!~].+)?", line)
            if m:
                name = m.group(1)
                version = None
                if "==" in line:
                    version = line.split("==", 1)[1].strip()
                version = (version or "").split(";")[0].strip() or None
                out.append({"ecosystem": "PyPI", "name": name, "version": version, "source": str(path)})
    return out


def parse_pipfile(path: Path):
    if toml_lib is None:
        return []
    with open(path, "rb") as f:
        data = toml_lib.load(f)
    out = []
    for section in ("packages", "dev-packages"):
        pkgs = data.get(section, {})
        for name, ver in pkgs.items():
            version = None
            if isinstance(ver, str):
                version = ver
            elif isinstance(ver, dict):
                version = ver.get("version")
            out.append({"ecosystem": "PyPI", "name": name, "version": version, "source": str(path)})
    return out


def parse_pyproject_toml(path: Path):
    if toml_lib is None:
        return []
    with open(path, "rb") as f:
        data = toml_lib.load(f)
    out = []
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        entries = poetry.get(section, {})
        for name, ver in entries.items():
            version = None
            if isinstance(ver, str):
                version = ver
            elif isinstance(ver, dict):
                version = ver.get("version")
            out.append({"ecosystem": "PyPI", "name": name, "version": version, "source": str(path)})
    project = data.get("project", {})
    deps = project.get("dependencies", []) or []
    for entry in deps:
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", entry)
        if m:
            name = m.group(1)
            ver = m.group(2).strip() or None
            out.append({"ecosystem": "PyPI", "name": name, "version": ver, "source": str(path)})
    return out


def parse_package_json(path: Path):
    out = []
    try:
        with open(path, "r", encoding="utf8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return out
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section, {}) or {}
        for name, ver in deps.items():
            version = re.sub(r'^[\^~><= ]+', '', ver or "")
            out.append({"ecosystem": "npm", "name": name, "version": version or None, "source": str(path)})
    return out


def parse_go_mod(path: Path):
    out = []
    text = path.read_text(encoding="utf8", errors="ignore")
    in_block = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            m = re.match(r"^([^\s]+)\s+([^\s]+)", line)
            if m:
                name = m.group(1)
                version = m.group(2)
                out.append({"ecosystem": "Go", "name": name, "version": version, "source": str(path)})
        else:
            m = re.match(r"^require\s+([^\s]+)\s+([^\s]+)", line)
            if m:
                out.append({"ecosystem": "Go", "name": m.group(1), "version": m.group(2), "source": str(path)})
    return out


def parse_pom_xml(path: Path):
    out = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        return out
    for dep in root.findall(".//{*}dependency"):
        group = dep.find("{*}groupId")
        artifact = dep.find("{*}artifactId")
        version = dep.find("{*}version")
        if group is not None and artifact is not None:
            name = f"{group.text.strip()}:{artifact.text.strip()}"
            out.append({"ecosystem": "Maven", "name": name, "version": (version.text.strip() if version is not None else None), "source": str(path)})
    return out


def extract_dependencies(root: Path):
    files = find_manifest_files(root)
    pkgs = []
    for p in files:
        n = p.name.lower()
        if n == "requirements.txt":
            pkgs += parse_requirements_txt(p)
        elif n == "pipfile":
            pkgs += parse_pipfile(p)
        elif n == "pyproject.toml":
            pkgs += parse_pyproject_toml(p)
        elif n == "package.json":
            pkgs += parse_package_json(p)
        elif n == "go.mod":
            pkgs += parse_go_mod(p)
        elif n == "pom.xml":
            pkgs += parse_pom_xml(p)
    return pkgs, files


