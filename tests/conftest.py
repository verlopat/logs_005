# conftest.py — shared pytest fixtures and path setup
import sys
from pathlib import Path

# Ensure project root is on sys.path so all package imports resolve
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
