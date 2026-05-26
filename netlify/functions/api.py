import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from mangum import Mangum

os.environ.setdefault("WAF_ENV", "production")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from backend.main import app

handler = Mangum(app, lifespan="off")
