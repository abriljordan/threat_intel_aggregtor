from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from . import db, socketio
from datetime import datetime
import json
import sys
import os
from dotenv import load_dotenv
from .models import User

# Add parent directory to path to import API clients
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Initialize blueprints
main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__, url_prefix='/auth')
api = Blueprint('api', __name__, url_prefix='/api')

# Load environment variables and initialize API clients
load_dotenv()

# Import API clients
from api_clients.abuseipdb_client import AbuseIPDBClient
from api_clients.virustotal_client import VirusTotalClient
from api_clients.shodan_client import ShodanClient

# Initialize API clients
abuseipdb_client = AbuseIPDBClient(os.getenv('ABUSEIPDB_API_KEY'))
virustotal_client = VirusTotalClient(os.getenv('VIRUSTOTAL_API_KEY'))
shodan_client = ShodanClient(os.getenv('SHODAN_API_KEY'))

# Main routes
@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@main.route('/search')
@login_required
def search():
    return render_template('search.html')

@main.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

# Auth routes
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('main.dashboard')
            return redirect(next_page)
            
        flash('Invalid username or password', 'danger')
        
    return render_template('auth/login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

# API routes
@api.route('/check/<target>', methods=['POST'])
@login_required
def check_target(target):
    try:
        data = request.get_json()
        apis = data.get('apis', ['abuseipdb', 'virustotal', 'shodan'])
        results = {}
        if 'abuseipdb' in apis:
            results['abuseipdb'] = abuseipdb_client.check_ip(target)
        if 'virustotal' in apis:
            results['virustotal'] = virustotal_client.check_ip(target)
        if 'shodan' in apis:
            results['shodan'] = shodan_client.check_ip(target)
        save_report(target, results)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/search', methods=['POST'])
@login_required
def search_shodan():
    try:
        data = request.get_json()
        query = data.get('query')
        if not query:
            return jsonify({'error': 'Query is required'}), 400
        # Use check_domain for domain search
        results = shodan_client.check_domain(query)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/reports')
@login_required
def get_reports():
    # TODO: Implement proper report retrieval from database
    return jsonify({
        'statistics': {
            'totalReports': 0,
            'highThreatReports': 0,
            'todayReports': 0,
            'avgThreatScore': 0
        },
        'charts': {
            'threatDistribution': {
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'reportsOverTime': {
                'labels': [],
                'data': []
            }
        },
        'reports': []
    })

def save_report(target, results):
    # TODO: Implement proper report saving to database
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'report_{target}_{timestamp}.json'
    
    with open(os.path.join(reports_dir, filename), 'w') as f:
        json.dump({
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }, f, indent=2)
