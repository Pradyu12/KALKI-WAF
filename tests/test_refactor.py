import httpx
import pytest
import time
import subprocess
import os
import signal

@pytest.fixture(scope="module", autouse=True)
def server():
    proc = subprocess.Popen(["python", "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8003"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    yield
    os.kill(proc.pid, signal.SIGTERM)

def test_dashboard():
    with httpx.Client(base_url="http://127.0.0.1:8003") as client:
        r = client.get("/")
        assert r.status_code == 200
        assert "KALKI" in r.text

def test_logo():
    with httpx.Client(base_url="http://127.0.0.1:8003") as client:
        r = client.get("/kalki_waf_logo.png")
        assert r.status_code == 200
