import httpx
import pytest
import time
import subprocess
import os
import signal

@pytest.fixture(scope="module", autouse=True)
def server():
    # Start the server on a different port for testing
    proc = subprocess.Popen(
        ["python", "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8002"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(2) # Wait for server to start
    yield
    # Kill the server
    os.kill(proc.pid, signal.SIGTERM)

def test_dashboard_access():
    with httpx.Client(base_url="http://127.0.0.1:8002") as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "<title>KALKI WAF | Security Command Center</title>" in response.text

def test_logo_access():
    with httpx.Client(base_url="http://127.0.0.1:8002") as client:
        response = client.get("/kalki_waf_logo.png?v=3.0")
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"
