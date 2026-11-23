"""Measure code coverage of src/ modules using Python's built-in trace module."""

import os
import sys
import trace
import unittest

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_dir = os.path.join(base_dir, "src")

    # Tracer ignoring system libraries
    tracer = trace.Trace(
        count=1,
        trace=0,
        ignoredirs=[sys.prefix, sys.exec_prefix]
    )

    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(base_dir, "tests"))

    runner = unittest.TextTestRunner(verbosity=1)
    
    print("Running test suite under tracer...")
    result = tracer.runfunc(runner.run, suite)

    # Inspect results for files in src/
    counts = tracer.results().counts

    print("\n" + "=" * 70)
    print("CODE COVERAGE REPORT (Built-in Trace): src/")
    print("=" * 70)

    total_executable_lines = 0
    total_covered_lines = 0

    src_files = [f for f in os.listdir(src_dir) if f.endswith(".py") and not f.startswith("__")]
    
    for f in sorted(src_files):
        fpath = os.path.join(src_dir, f)
        # Read lines of code to find executable lines
        with open(fpath, "r", encoding="utf-8") as fp:
            code_lines = fp.readlines()

        executable_in_file = 0
        covered_in_file = 0

        for line_num, line in enumerate(code_lines, start=1):
            s = line.strip()
            # Basic heuristic for non-empty, non-comment lines
            if not s or s.startswith("#") or s.startswith('"""') or s.startswith("'''"):
                continue
            
            executable_in_file += 1
            # Check if this line was executed
            # trace counts key is (filename, lineno)
            # Normalize path
            hit = counts.get((fpath, line_num), 0)
            if hit > 0:
                covered_in_file += 1

        pct = (covered_in_file / executable_in_file * 100.0) if executable_in_file > 0 else 100.0
        print(f"{f:<30} | {covered_in_file:>5} / {executable_in_file:>5} lines | {pct:>6.2f}%")
        
        total_executable_lines += executable_in_file
        total_covered_lines += covered_in_file

    print("-" * 70)
    overall_pct = (total_covered_lines / total_executable_lines * 100.0) if total_executable_lines > 0 else 100.0
    print(f"{'OVERALL src/ COVERAGE':<30} | {total_covered_lines:>5} / {total_executable_lines:>5} lines | {overall_pct:>6.2f}%")
    print("=" * 70)

if __name__ == "__main__":
    main()
