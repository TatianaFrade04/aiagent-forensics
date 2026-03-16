"""
Pytest configuration — adds the project root to sys.path so that
``import agent.*`` resolves correctly when running from any directory.
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
