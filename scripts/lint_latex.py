"""LaTeX Linter for ICMLDE Procedia Computer Science Manuscript.
Validates:
1. No unescaped '%' character inside tabular/table environments.
2. Every table row has the exact number of column cells defined in the header.
3. No hardcoded floating-point / percentage numbers in Abstract and Conclusion (must use macros).
4. No prohibited phrases ("forward secrecy", "proven contain", "zero leakage", "mathematical proof of containment").
5. Every result macro referenced in the text exists in results_macros.tex.
6. All citation keys exist in thebibliography.
"""

import os
import re
import sys

PROHIBITED_PHRASES = [
    r"\bforward\s*secrecy\b",
    r"\bproven\s+contain",
    r"\bzero\s+leakage\b",
    r"\bmathematical\s+proof\s+of\s+containment\b",
]

def lint_file(file_path: str, known_macros: set[str] | None = None) -> list[str]:
    errors = []
    if not os.path.exists(file_path):
        return [f"File not found: {file_path}"]

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    in_tabular = False
    in_abstract = False
    in_conclusion = False
    expected_cols = 0
    tabular_line_start = 0

    col_def_regex = re.compile(r"\\begin\{tabular\*?\}\{?([^{}]*)\}?\{([^}]+)\}")
    simple_col_regex = re.compile(r"\\begin\{tabular\*?\}\{([^}]+)\}")

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        # Check prohibited phrases (ignore commented-out lines)
        if not line.startswith("%"):
            for pattern in PROHIBITED_PHRASES:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(
                        f"[{os.path.basename(file_path)}:{idx}] Prohibited phrase matched '{pattern}': "
                        f"{line[:70]}..."
                    )

        # Check section boundaries
        if "\\begin{abstract}" in line:
            in_abstract = True
            continue
        if "\\end{abstract}" in line:
            in_abstract = False
            continue

        if "\\section{Conclusion}" in line or "\\section{Conclusion and Future Work}" in line:
            in_conclusion = True
            continue
        if in_conclusion and line.startswith("\\section"):
            in_conclusion = False
            continue

        # Check tabular environment
        if "\\begin{tabular" in line:
            in_tabular = True
            tabular_line_start = idx
            m = col_def_regex.search(line)
            if m:
                col_spec = m.group(2)
            else:
                m2 = simple_col_regex.search(line)
                col_spec = m2.group(1) if m2 else ""
            
            clean_spec = re.sub(r"[@*!|><}{]|extracolsep|textwidth|\\[a-z]+", "", col_spec)
            expected_cols = sum(1 for c in clean_spec if c in "lcrpmb")
            continue

        if "\\end{tabular" in line:
            in_tabular = False
            expected_cols = 0
            continue

        if in_tabular:
            # 1. Check for unescaped % inside tabular
            unescaped_pct = re.search(r"(?<!\\)%", line)
            if unescaped_pct:
                errors.append(
                    f"[{os.path.basename(file_path)}:{idx}] Unescaped '%' inside tabular environment! "
                    f"Line: {line[:60]}..."
                )

            # 2. Check for inverted punctuation (¡ or ¿) or bare < / > in text mode
            if "¡" in line or "¿" in line:
                errors.append(
                    f"[{os.path.basename(file_path)}:{idx}] Inverted punctuation character (¡ or ¿) detected in tabular! "
                    f"Line: {line[:60]}..."
                )

            # Remove all math mode blocks $...$ and \[...\] before checking for bare < or >
            line_no_math = re.sub(r"\$[^\$]*\$", "", line)
            line_no_math = re.sub(r"\\\[.*?\\\]", "", line_no_math)
            # Exclude lines that are purely tabular headers / column definitions
            if not line.startswith(r"\begin{tabular") and not line.startswith(r"\end{tabular") and not line.startswith(r"\multicolumn"):
                bare_angles = re.search(r"(?<!\\)[<>]", line_no_math)
                if bare_angles:
                    errors.append(
                        f"[{os.path.basename(file_path)}:{idx}] Bare angle bracket '<' or '>' in tabular text mode (must use math mode $\\le$ or $<$): "
                        f"Line: {line[:60]}..."
                    )

            # 3. Check row column count
            if re.search(r"(?<!\\)&", line) and "\\\\" in line:
                cells = re.split(r"(?<!\\)&", line)
                if expected_cols > 0 and len(cells) != expected_cols:
                    if "\\multicolumn" not in line and "\\cmidrule" not in line:
                        errors.append(
                            f"[{os.path.basename(file_path)}:{idx}] Row column count mismatch: "
                            f"expected {expected_cols}, got {len(cells)}. Line: {line[:60]}..."
                        )

        # 3. Check for hardcoded floating point numbers or percentages in Abstract / Conclusion
        if in_abstract or in_conclusion:
            if not line.startswith("%") and not line.startswith("\\"):
                tokens = line.split()
                for t in tokens:
                    if re.search(r"\b\d+\.\d+\\?%", t) and "\\" not in t.split("%")[0]:
                        errors.append(
                            f"[{os.path.basename(file_path)}:{idx}] Potential hard-coded percentage in "
                            f"{'Abstract' if in_abstract else 'Conclusion'}: '{t}'. Must use macro."
                        )

    return errors

def collect_defined_macros(macros_path: str) -> set[str]:
    """Collect all macro names defined via \newcommand in results_macros.tex."""
    macros = set()
    if not os.path.exists(macros_path):
        return macros
    with open(macros_path, "r", encoding="utf-8") as f:
        content = f.read()
    for m in re.finditer(r"\\newcommand\{\\([A-Za-z0-9]+)\}", content):
        macros.add(m.group(1))
    return macros

def check_undefined_result_macros(file_path: str, defined_macros: set[str]) -> list[str]:
    """Check if file references result macros that are not defined."""
    errors = []
    if not os.path.exists(file_path):
        return errors
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Search for macro invocations like \benchmarkCPU, \mlAgreementKEighteen, etc.
    # We identify result macros by common prefixes or by checking against defined
    prefixes = (
        "benchmark", "bench", "cipher", "npcr", "uaci", "maxCorrelation", "chiSquare",
        "encTime", "decTime", "throughput", "overhead", "analytical", "mono",
        "psnrGain", "eprValue", "figTwo", "security", "ml",
        "header", "record", "pbkdf", "handshake", "load", "deltaOpenCv"
    )
    for m in re.finditer(r"\\([A-Za-z0-9]+)", content):
        name = m.group(1)
        if any(name.startswith(p) for p in prefixes):
            if name not in defined_macros:
                errors.append(
                    f"[{os.path.basename(file_path)}] Undefined result macro '\\{name}' referenced!"
                )
    return errors

def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    files_to_lint = []

    paper_tex = os.path.join(root_dir, "paper_icmlde", "sw.tex")
    if os.path.exists(paper_tex):
        files_to_lint.append(paper_tex)

    tables_dir = os.path.join(root_dir, "paper_icmlde", "tables")
    if os.path.exists(tables_dir):
        for f in os.listdir(tables_dir):
            if f.endswith(".tex"):
                files_to_lint.append(os.path.join(tables_dir, f))

    macros_file = os.path.join(tables_dir, "results_macros.tex")
    if not os.path.exists(macros_file):
        macros_file = os.path.join(root_dir, "tables", "results_macros.tex")
    
    defined_macros = collect_defined_macros(macros_file)
    print(f"Loaded {len(defined_macros)} defined macros from {os.path.basename(macros_file)}.")

    print(f"Linting {len(files_to_lint)} LaTeX files...")
    all_errors = []
    for fp in files_to_lint:
        errs = lint_file(fp, defined_macros)
        if errs:
            all_errors.extend(errs)
        
        # Check macro definitions
        macro_errs = check_undefined_result_macros(fp, defined_macros)
        if macro_errs:
            all_errors.extend(macro_errs)

    # Check citations in sw.tex
    if os.path.exists(paper_tex):
        with open(paper_tex, "r", encoding="utf-8") as f:
            content = f.read()
        
        bibitems = set(re.findall(r"\\bibitem\{([^}]+)\}", content))
        
        cites = set()
        for fp in files_to_lint:
            with open(fp, "r", encoding="utf-8") as f:
                c_text = f.read()
            for c_match in re.findall(r"\\cite\{([^}]+)\}", c_text):
                for k in c_match.split(","):
                    cites.add(k.strip())
        
        undefined_cites = cites - bibitems
        if undefined_cites:
            all_errors.append(f"Undefined citation keys: {undefined_cites}")
            
        unused_bibitems = bibitems - cites
        if unused_bibitems:
            all_errors.append(f"Unused bibitem keys in thebibliography: {unused_bibitems}")

    if all_errors:
        print(f"\n[FAILED] Found {len(all_errors)} LaTeX lint errors:")
        for e in all_errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("[SUCCESS] All LaTeX files passed lint checks with zero errors.")

if __name__ == "__main__":
    main()
