import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "corpus"


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
