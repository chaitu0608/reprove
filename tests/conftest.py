import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "corpus"

# src-layout bootstrap: tests run straight from a checkout, with or without
# an editable install (and regardless of filesystem quirks that can disable it).
_SRC = str(REPO / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


@pytest.fixture()
def vuln_app(tmp_path):
    dst = tmp_path / "vuln-node-api"
    shutil.copytree(CORPUS / "vuln-node-api", dst)
    return dst


@pytest.fixture()
def clean_app(tmp_path):
    dst = tmp_path / "clean-node-api"
    shutil.copytree(CORPUS / "clean-node-api", dst)
    return dst


@pytest.fixture()
def nextlike_app(tmp_path):
    dst = tmp_path / "vuln-static-nextlike"
    shutil.copytree(CORPUS / "vuln-static-nextlike", dst)
    return dst
