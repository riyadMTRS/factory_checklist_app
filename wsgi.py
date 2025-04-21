import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import the create_app function
from app import app

if __name__ == '__main__':
    # Get host and port from environment or use defaults
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    # Run the app
    app.run(host=host, port=port) 