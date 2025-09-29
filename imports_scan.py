import os
import ast


def get_imports_from_file(filepath):
    imports = set()
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError:
            return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0].lower())
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0].lower())
    return imports


def scan_project_imports(project_path="."):
    all_imports = set()
    for root, _, files in os.walk(project_path):
        for file in files:
            if file.endswith(".py"):
                all_imports |= get_imports_from_file(os.path.join(root, file))
    return all_imports


