"""
Evaluation entry point for HackerRank Orchestrate: Ghost Data Still Exists.
Runs the evaluation benchmark against sample_deletion_requests.csv.
"""
import sys
import os

# Add repo root and code directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir) if os.path.basename(parent_dir) == 'code' else parent_dir

for p in [root_dir, os.path.join(root_dir, 'code'), parent_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from main import main

if __name__ == '__main__':
    # Default to evaluate mode
    if '--evaluate' not in sys.argv:
        sys.argv.append('--evaluate')
    main()
