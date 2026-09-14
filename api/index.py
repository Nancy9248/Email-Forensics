import sys
import os

# Add app directory to Python path
app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from server import app

# Export WSGI app for Vercel Serverless
app = app
