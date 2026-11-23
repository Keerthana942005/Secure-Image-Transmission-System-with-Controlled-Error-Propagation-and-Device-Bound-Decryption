import os
import re

tables_dir = "paper_icmlde/tables"

for f in sorted(os.listdir(tables_dir)):
    if not f.endswith(".tex") or f == "results_macros.tex":
        continue
    fpath = os.path.join(tables_dir, f)
    with open(fpath, "r", encoding="utf-8") as fp:
        lines = fp.readlines()

    row_count = 0
    unescaped_pcts = 0
    for idx, l in enumerate(lines, 1):
        if "&" in l and "\\\\" in l:
            row_count += 1
        # Check for unescaped %
        if re.search(r"(?<!\\)%", l):
            unescaped_pcts += 1
            print(f"  [UNESCAPED %] {f}:{idx}: {l.strip()}")

    print(f"{f:<25} | Data Rows: {row_count:>2} | Unescaped %: {unescaped_pcts}")

