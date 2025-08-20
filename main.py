import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging for deployment
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class Base(DeclarativeBase):
    pass

# Create Flask app
app = Flask(__name__)

# Configure for Google Cloud
app.secret_key = os.environ.get("SESSION_SECRET", "antidote_secret_key_2025_production_secure")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Simple health check
@app.route('/health')
def health():
    return {'status': 'healthy', 'service': 'antidote'}, 200

# Simple test route
@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Antidote - Medical Aesthetic Marketplace</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #00A0B0; }
        </style>
    </head>
    <body>
        <h1>🏥 Antidote Medical Aesthetic Marketplace</h1>
        <p>✅ Successfully deployed to Google Cloud Mumbai!</p>
        <p>🚀 Ready for 40x performance improvement</p>
        <p>📍 Running in Mumbai region for optimal database performance</p>
    </body>
    </html>
    '''

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
