"""
Evaluation Benchmark Runner for Ghost Data Still Exists.
"""
import sys
import os
import subprocess

def run_evaluation():
    print("Running Ghost Data Still Exists Evaluation Benchmark...")
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main_script = os.path.join(repo_root, "code", "main.py")
    cmd = [sys.executable, main_script, "--evaluate"]
    result = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

if __name__ == '__main__':
    run_evaluation()
