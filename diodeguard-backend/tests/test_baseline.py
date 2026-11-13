"""Baseline test verifying backend configuration and directory layout"""

import os
from pathlib import Path


def test_project_structure():
    base_dir = Path(__file__).resolve().parent.parent
    assert (base_dir / "app").is_dir()
    assert (base_dir / "alembic").is_dir()
    assert (base_dir / "app" / "main.py").is_file()
    assert (base_dir / "app" / "database.py").is_file()
    assert (base_dir / "requirements.txt").is_file()
