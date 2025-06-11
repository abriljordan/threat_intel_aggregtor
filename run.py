from web_dashboard import create_app
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create Flask application
app = create_app()

if __name__ == '__main__':
    # Run the application in debug mode
    app.run(debug=True, host='0.0.0.0', port=5000) 