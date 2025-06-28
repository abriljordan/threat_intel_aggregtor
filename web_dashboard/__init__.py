from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from dotenv import load_dotenv
import os

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()

def create_app():
    # Create Flask application
    app = Flask(__name__)
    
    # Load environment variables
    load_dotenv()
    
    # Configure the application
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-please-change')
    
    # Use PostgreSQL if available, fallback to SQLite
    database_url = os.getenv('THREAT_INTEL_DATABASE_URL')
    if database_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print(f"Using PostgreSQL database: {database_url.split('@')[1] if '@' in database_url else database_url}")
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threat_intel.db'
        print("Using SQLite database (fallback)")
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    
    # Set login view
    login_manager.login_view = 'auth.login'
    
    # Import models to ensure user loader is registered
    from . import models
    
    # Import blueprints
    from web_dashboard.routes import main, auth, api, network, threat_intel
    
    # Register blueprints
    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(api)
    app.register_blueprint(network)
    app.register_blueprint(threat_intel)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create a default user if none exists
        from .models import User
        if not User.query.first():
            user = User(username='admin', email='admin@example.com')
            user.set_password('admin123')
            db.session.add(user)
            db.session.commit()
        
        # Initialize RSS processor for background caching
        try:
            from data_sources.rss_feeds import get_rss_processor
            rss_processor = get_rss_processor()
            print("RSS processor initialized - background caching started")
        except Exception as e:
            print(f"Warning: Could not initialize RSS processor: {e}")
    
    return app
