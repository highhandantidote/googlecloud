from app import create_app
import os
import logging

# Configure logging for deployment
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create the Flask application
app = create_app()

# Register health check for Google Cloud
from health_check import health_bp
app.register_blueprint(health_bp)

# Ensure the app binds to 0.0.0.0:5000 explicitly for deployment
app.config['SERVER_NAME'] = None  # Allow any host for deployment

if __name__ == "__main__":
    # Run the Flask application with explicit host and port binding
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
