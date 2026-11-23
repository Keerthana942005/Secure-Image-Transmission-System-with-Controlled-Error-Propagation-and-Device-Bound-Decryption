"""Platform-independent task runner for Secure Image Transmission System.
Usage:
    python tasks.py test
    python tasks.py exp
    python tasks.py tables
    python tasks.py figures
    python tasks.py lint
    python tasks.py app
    python tasks.py clean
    python tasks.py all
"""

import os
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def run_cmd(cmd: list[str]) -> int:
    print(f"\n[RUNNING] {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=BASE_DIR)
    if result.returncode != 0:
        print(f"[FAILED] Command exited with code {result.returncode}")
    return result.returncode

def task_test() -> int:
    return run_cmd([sys.executable, "-m", "unittest", "discover", "tests"])

def task_exp() -> int:
    return run_cmd([sys.executable, os.path.join("experiments", "run_all.py")])

def task_tables() -> int:
    return run_cmd([sys.executable, os.path.join("scripts", "make_tables.py")])

def task_figures() -> int:
    return run_cmd([sys.executable, os.path.join("scripts", "make_figures.py")])

def task_lint() -> int:
    return run_cmd([sys.executable, os.path.join("scripts", "lint_latex.py")])

def task_app() -> int:
    return run_cmd([sys.executable, "-m", "streamlit", "run", "app.py"])

def task_clean() -> int:
    print("[CLEAN] Cleaning __pycache__ and temporary artifacts...")
    count = 0
    for root, dirs, files in os.walk(BASE_DIR):
        for d in dirs:
            if d in ("__pycache__", ".pytest_cache"):
                p = os.path.join(root, d)
                try:
                    shutil.rmtree(p)
                    count += 1
                except Exception as e:
                    print(f"  Warning: could not remove {p}: {e}")
        for f in files:
            if f.endswith((".pyc", ".pyo", ".coverage")):
                p = os.path.join(root, f)
                try:
                    os.remove(p)
                    count += 1
                except Exception as e:
                    print(f"  Warning: could not remove {p}: {e}")
    print(f"[CLEAN] Removed {count} items.")
    return 0

def task_all() -> int:
    print("[ALL] Running comprehensive pipeline: test -> tables -> figures -> lint...")
    for step in [task_test, task_tables, task_figures, task_lint]:
        rc = step()
        if rc != 0:
            print(f"[ALL] Step failed with returncode {rc}. Aborting.")
            return rc
    print("[ALL] Pipeline completed successfully!")
    return 0

def print_help():
    print(__doc__)

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    target = sys.argv[1].lower()
    targets = {
        "test": task_test,
        "exp": task_exp,
        "tables": task_tables,
        "figures": task_figures,
        "lint": task_lint,
        "app": task_app,
        "clean": task_clean,
        "all": task_all,
    }

    if target in targets:
        rc = targets[target]()
        sys.exit(rc)
    else:
        print(f"Unknown target: '{target}'. Available targets: {list(targets.keys())}")
        sys.exit(1)

if __name__ == "__main__":
    main()

