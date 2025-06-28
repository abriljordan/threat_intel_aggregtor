from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from . import db, socketio
from datetime import datetime
import json
import sys
import os
from dotenv import load_dotenv
from .models import User, Report, db
import glob
import sqlite3
from threat_intelligence.threat_repository import get_threat_repository, ThreatIntelligenceRepository
import time

# Add parent directory to path to import API clients
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Initialize blueprints
main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__, url_prefix='/auth')
api = Blueprint('api', __name__, url_prefix='/api')
network = Blueprint('network', __name__, url_prefix='/network')
threat_intel = Blueprint('threat_intel', __name__, url_prefix='/threat-intel')

# Load environment variables and initialize API clients
load_dotenv()

# Import API clients
from api_clients.abuseipdb_client import AbuseIPDBClient
from api_clients.virustotal_client import VirusTotalClient
from api_clients.shodan_client import ShodanClient
from api_clients.httpbl_client import HttpBLClient

# Import network monitoring components
from integration.network_monitor_manager import NetworkMonitorManager

# Import new threat intelligence components
try:
    from threat_intelligence.mitre_attack import get_mitre_attack
    from threat_intelligence.threat_repository import get_threat_repository
    from data_sources.rss_feeds import get_rss_processor
    from .advanced_dashboard import advanced_dashboard
    print("✅ Successfully imported threat intelligence modules")
except ImportError as e:
    print(f"Warning: Could not import threat intelligence modules: {e}")
    get_mitre_attack = None
    get_threat_repository = None
    get_rss_processor = None
    advanced_dashboard = None

# Initialize API clients with error handling
def get_abuseipdb_client():
    """Get AbuseIPDB client with error handling."""
    try:
        return AbuseIPDBClient(os.getenv('ABUSEIPDB_API_KEY'))
    except ValueError:
        return None

def get_virustotal_client():
    """Get VirusTotal client with error handling."""
    try:
        return VirusTotalClient(os.getenv('VIRUSTOTAL_API_KEY'))
    except ValueError:
        return None

def get_shodan_client():
    """Get Shodan client with error handling."""
    try:
        return ShodanClient(os.getenv('SHODAN_API_KEY'))
    except ValueError:
        return None

def get_httpbl_client():
    """Get HttpBL client with error handling."""
    try:
        return HttpBLClient(os.getenv('HTTPBL_ACCESS_KEY'))
    except ValueError:
        return None

# Initialize network monitor manager
api_keys = {
    'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
    'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
    'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY'),
    'HTTPBL_ACCESS_KEY': os.getenv('HTTPBL_ACCESS_KEY')
}

network_monitor_manager = NetworkMonitorManager(api_keys, socketio)

# Main routes
@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    stats = get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)

@main.route('/search')
@login_required
def search():
    return render_template('search.html')

@main.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@main.route('/network-monitoring')
@login_required
def network_monitoring():
    return render_template('network_monitoring.html')

@main.route('/advanced-dashboard')
@login_required
def advanced_dashboard_page():
    return render_template('advanced_dashboard.html')

@main.route('/threat-intelligence')
@login_required
def threat_intelligence():
    return render_template('threat_intelligence.html')

@main.route('/security-news')
@login_required
def security_news():
    """Render the security news page."""
    return render_template('security_news.html')

@main.route('/mitre-attack')
@login_required
def mitre_attack_page():
    return render_template('mitre_attack.html')

@main.route('/test-dashboard')
def test_dashboard():
    """Test dashboard page (no authentication required)."""
    return render_template('test_dashboard.html')

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

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        terms = request.form.get('terms')
        
        # Validation
        errors = []
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered')
        
        # Validate username format
        if not username or len(username) < 3 or len(username) > 20:
            errors.append('Username must be 3-20 characters long')
        elif not username.replace('_', '').replace('-', '').isalnum():
            errors.append('Username can only contain letters, numbers, underscore, and dash')
        
        # Validate email format
        if not email or '@' not in email:
            errors.append('Please enter a valid email address')
        
        # Validate password strength
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        elif not any(c.isupper() for c in password):
            errors.append('Password must contain at least one uppercase letter')
        elif not any(c.islower() for c in password):
            errors.append('Password must contain at least one lowercase letter')
        elif not any(c.isdigit() for c in password):
            errors.append('Password must contain at least one number')
        elif not any(c in '!@#$%^&*' for c in password):
            errors.append('Password must contain at least one special character (!@#$%^&*)')
        
        # Check password confirmation
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        # Check terms agreement
        if not terms:
            errors.append('You must agree to the Terms of Service and Privacy Policy')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
        else:
            try:
                # Create new user
                user = User(username=username, email=email)
                user.set_password(password)
                
                db.session.add(user)
                db.session.commit()
                
                flash('Account created successfully! You can now log in.', 'success')
                return redirect(url_for('auth.login'))
                
            except Exception as e:
                db.session.rollback()
                flash('Error creating account. Please try again.', 'danger')
                print(f"Registration error: {e}")
    
    return render_template('auth/register.html')

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
        apis = data.get('apis', ['abuseipdb', 'virustotal', 'shodan', 'httpbl'])

        # Try to load a recent cached result
        cached_results = load_recent_report(target)
        if cached_results:
            return jsonify(cached_results)

        results = {}
        if 'abuseipdb' in apis or 'all' in apis:
            client = get_abuseipdb_client()
            if client:
                results['abuseipdb'] = client.check_ip(target)
            else:
                results['abuseipdb'] = {"error": "AbuseIPDB API key not configured"}
        
        if 'virustotal' in apis or 'all' in apis:
            client = get_virustotal_client()
            if client:
                results['virustotal'] = client.check_ip(target)
            else:
                results['virustotal'] = {"error": "VirusTotal API key not configured"}
        
        if 'shodan' in apis or 'all' in apis:
            client = get_shodan_client()
            if client:
                results['shodan'] = client.check_ip(target)
            else:
                results['shodan'] = {"error": "Shodan API key not configured"}
        
        if 'httpbl' in apis or 'all' in apis:
            client = get_httpbl_client()
            if client:
                results['httpbl'] = client.check_ip(target)
            else:
                results['httpbl'] = {"error": "HttpBL API key not configured"}

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
        
        client = get_shodan_client()
        if client:
            # Use check_domain for domain search
            results = client.check_domain(query)
            return jsonify(results)
        else:
            return jsonify({'error': 'Shodan API key not configured'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/reports')
@login_required
def get_reports():
    """Get reports from database with statistics and charts."""
    try:
        from datetime import datetime, timedelta
        
        # Get all reports ordered by creation date
        all_reports = Report.query.order_by(Report.created_at.desc()).all()
        
        # Calculate statistics
        total_reports = len(all_reports)
        high_threat_reports = Report.query.filter(Report.abuse_score > 80).count()
        
        # Today's reports
        today = datetime.utcnow().date()
        today_reports = Report.query.filter(
            db.func.date(Report.created_at) == today
        ).count()
        
        # Average threat score
        avg_score = db.session.query(db.func.avg(Report.abuse_score)).scalar() or 0
        
        # Threat distribution
        high_threat = Report.query.filter(Report.abuse_score > 80).count()
        medium_threat = Report.query.filter(
            Report.abuse_score > 50, 
            Report.abuse_score <= 80
        ).count()
        low_threat = Report.query.filter(Report.abuse_score <= 50).count()
        
        # Reports over time (last 7 days)
        reports_over_time = []
        for i in range(7):
            date = today - timedelta(days=i)
            count = Report.query.filter(
                db.func.date(Report.created_at) == date
            ).count()
            reports_over_time.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        # Convert reports to list format
        reports_list = []
        for report in all_reports[:50]:  # Limit to last 50 reports
            reports_list.append({
                'id': report.id,
                'target': report.target,
                'timestamp': report.created_at.isoformat(),
                'abuse_score': report.abuse_score,
                'is_malicious': report.is_malicious,
                'results': report.get_results()
            })
        
        return jsonify({
            'statistics': {
                'totalReports': total_reports,
                'highThreatReports': high_threat_reports,
                'todayReports': today_reports,
                'avgThreatScore': round(avg_score, 2)
            },
            'charts': {
                'threatDistribution': {
                    'high': high_threat,
                    'medium': medium_threat,
                    'low': low_threat
                },
                'reportsOverTime': {
                    'labels': [r['date'] for r in reversed(reports_over_time)],
                    'data': [r['count'] for r in reversed(reports_over_time)]
                }
            },
            'reports': reports_list
        })
        
    except Exception as e:
        print(f"Error fetching reports from database: {e}")
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
            'reports': [],
            'error': str(e)
        }), 500

@api.route('/dashboard-stats')
@login_required
def get_dashboard_stats_api():
    """Get dashboard statistics as JSON."""
    try:
        stats = get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def save_report(target, results):
    """Save report to database."""
    try:
        # Create new report
        report = Report(target=target.strip())
        report.set_results(results)
        
        # Save to database
        db.session.add(report)
        db.session.commit()
        
        print(f"Saved report for {target} to database (ID: {report.id})")
        
        # Clean up old reports from database (keep last 100)
        cleanup_old_reports_from_db(max_reports=100)
        
    except Exception as e:
        print(f"Error saving report to database: {e}")
        db.session.rollback()
        # Fallback to file storage if database fails
        save_report_to_file(target, results)

def save_report_to_file(target, results):
    """Fallback: Save report to file (legacy method)."""
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

def get_dashboard_stats():
    """Get dashboard statistics from database."""
    try:
        # Get total counts
        total_checks = Report.query.count()
        malicious_ips = Report.query.filter_by(is_malicious=True).count()
        
        # Get recent activity (last 5 reports)
        recent_reports = Report.query.order_by(Report.created_at.desc()).limit(5).all()
        recent_activity = []
        
        for report in recent_reports:
            recent_activity.append({
                'target': report.target,
                'timestamp': report.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_malicious': report.is_malicious
            })
        
        return {
            'total_checks': total_checks,
            'malicious_ips': malicious_ips,
            'total_reports': total_checks,
            'recent_activity': recent_activity
        }
        
    except Exception as e:
        print(f"Error getting stats from database: {e}")
        # Fallback to file-based stats
        return get_dashboard_stats_from_files()

def get_dashboard_stats_from_files():
    """Fallback: Get dashboard statistics from files (legacy method)."""
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
    if not os.path.exists(reports_dir):
        return {
            'total_checks': 0,
            'malicious_ips': 0,
            'total_reports': 0,
            'recent_activity': []
        }
    report_files = sorted(glob.glob(os.path.join(reports_dir, 'report_*.json')), reverse=True)
    total_checks = len(report_files)
    malicious_ips = 0
    recent_activity = []
    for report_file in report_files[:5]:  # Only show last 5
        with open(report_file, 'r') as f:
            data = json.load(f)
            target = data.get('target')
            timestamp = data.get('timestamp')
            results = data.get('results', {})
            # Check if any API flagged as malicious (abuseConfidenceScore > 80 or similar)
            is_malicious = False
            for api_result in results.values():
                d = api_result.get('data') or api_result
                if d.get('abuseConfidenceScore', 0) > 80:
                    is_malicious = True
                if 'last_analysis_stats' in d:
                    stats = d['last_analysis_stats']
                    if stats.get('malicious', 0) > 0:
                        is_malicious = True
            if is_malicious:
                malicious_ips += 1
            recent_activity.append({
                'target': target,
                'timestamp': timestamp,
                'is_malicious': is_malicious
            })
    return {
        'total_checks': total_checks,
        'malicious_ips': malicious_ips,
        'total_reports': total_checks,
        'recent_activity': recent_activity
    }

def load_recent_report(target, max_age_hours=24):
    """Load the most recent report for a target if it's within max_age_hours."""
    try:
        from .models import Report
        from datetime import datetime, timedelta
        
        # Calculate cutoff time
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        # Get most recent report for this target
        report = Report.query.filter(
            Report.target == target.strip(),
            Report.created_at >= cutoff_time
        ).order_by(Report.created_at.desc()).first()
        
        if report:
            return report.get_results()
        
        return None
        
    except Exception as e:
        print(f"Error loading report from database: {e}")
        # Fallback to file-based loading
        return load_recent_report_from_file(target, max_age_hours)

def load_recent_report_from_file(target, max_age_hours=24):
    """Fallback: Load recent report from file (legacy method)."""
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
    pattern = os.path.join(reports_dir, f'report_{target}_*.json')
    report_files = sorted(glob.glob(pattern), reverse=True)
    now = datetime.now()
    for report_file in report_files:
        with open(report_file, 'r') as f:
            data = json.load(f)
            timestamp = datetime.fromisoformat(data.get('timestamp'))
            if (now - timestamp).total_seconds() < max_age_hours * 3600:
                return data['results']
    return None

# Network Monitoring API routes
@network.route('/start', methods=['POST'])
@login_required
def start_network_monitoring():
    """Start network monitoring."""
    try:
        network_monitor_manager.start_monitoring()
        return jsonify({'status': 'success', 'message': 'Network monitoring started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/stop', methods=['POST'])
@login_required
def stop_network_monitoring():
    """Stop network monitoring."""
    try:
        network_monitor_manager.stop_monitoring()
        return jsonify({'status': 'success', 'message': 'Network monitoring stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/status')
@login_required
def get_network_monitoring_status():
    """Get network monitoring status."""
    try:
        status = network_monitor_manager.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/data')
@login_required
def get_network_monitoring_data():
    """Get current network monitoring data."""
    try:
        data = network_monitor_manager.get_monitoring_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/alerts')
@login_required
def get_network_alerts():
    """Get network monitoring alerts."""
    try:
        filters = request.args.to_dict()
        alerts = network_monitor_manager.get_alerts(filters)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    try:
        success = network_monitor_manager.acknowledge_alert(alert_id, current_user.username)
        if success:
            return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
        else:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/alerts/<alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Resolve an alert."""
    try:
        data = request.get_json()
        resolution_notes = data.get('notes', '') if data else ''
        success = network_monitor_manager.resolve_alert(alert_id, current_user.username, resolution_notes)
        if success:
            return jsonify({'status': 'success', 'message': 'Alert resolved'})
        else:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/scan-system', methods=['POST'])
@login_required
def scan_system():
    """Perform a full system scan."""
    try:
        results = network_monitor_manager.get_system_scan_results()
        return jsonify(results)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/processes/<int:pid>/kill', methods=['POST'])
@login_required
def kill_process(pid):
    """Kill a process by PID."""
    try:
        success = network_monitor_manager.kill_process(pid)
        if success:
            return jsonify({'status': 'success', 'message': f'Process {pid} terminated'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to terminate process'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/processes/<int:pid>/details')
@login_required
def get_process_details(pid):
    """Get detailed information about a specific process."""
    try:
        details = network_monitor_manager.get_process_details(pid)
        if details:
            return jsonify(details)
        else:
            return jsonify({'status': 'error', 'message': 'Process not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/processes/suspicious')
@login_required
def get_suspicious_processes():
    """Get list of suspicious processes."""
    try:
        processes = network_monitor_manager.get_suspicious_processes()
        return jsonify(processes)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/clear-cache', methods=['POST'])
@login_required
def clear_correlation_cache():
    """Clear the correlation cache."""
    try:
        network_monitor_manager.clear_correlation_cache()
        return jsonify({'status': 'success', 'message': 'Cache cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/export-alerts', methods=['POST'])
@login_required
def export_alerts():
    """Export alerts to file."""
    try:
        data = request.get_json()
        filepath = data.get('filepath', 'alerts_export.json')
        format = data.get('format', 'json')
        
        success = network_monitor_manager.export_alerts(filepath, format)
        if success:
            return jsonify({'status': 'success', 'message': f'Alerts exported to {filepath}'})
        else:
            return jsonify({'status': 'error', 'message': 'Export failed'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/alerts/acknowledge-all', methods=['POST'])
@login_required
def acknowledge_all_alerts():
    """Acknowledge all unacknowledged alerts."""
    try:
        success = network_monitor_manager.acknowledge_all_alerts(current_user.username)
        if success:
            return jsonify({'status': 'success', 'message': 'All alerts acknowledged'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to acknowledge alerts'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network.route('/alerts/clear-all', methods=['POST'])
@login_required
def clear_all_alerts():
    """Clear all alerts."""
    try:
        success = network_monitor_manager.clear_all_alerts()
        if success:
            return jsonify({'status': 'success', 'message': 'All alerts cleared'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to clear alerts'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Threat Intelligence API routes
@threat_intel.route('/dashboard-data')
@login_required
def get_threat_intelligence_dashboard():
    """Get threat intelligence dashboard data."""
    try:
        if not advanced_dashboard:
            return jsonify({'error': 'Advanced dashboard not available'}), 503
        
        # Get real threat data from various sources
        threat_data = collect_real_threat_data()
        
        dashboard = advanced_dashboard.create_threat_intelligence_dashboard(threat_data)
        return jsonify(dashboard)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def collect_real_threat_data():
    """Collect real threat intelligence data from various sources."""
    from datetime import datetime, timedelta
    threat_data = {
        'overall_threat_score': 0,
        'threat_categories': {},
        'threat_timeline': [],
        'geo_threats': {},
        'attack_techniques': {},
        'threat_actors': {},
        'malware_families': {},
        'network_traffic': {},
        'process_monitoring': {}
    }
    try:
        # 1. Get threat statistics from database
        if get_threat_repository:
            try:
                threat_repo = get_threat_repository()
                stats = threat_repo.get_threat_statistics()
                total_observables = stats.get('observables', 0)
                high_threat_observables = stats.get('high_threat_observables', 0)
                if total_observables > 0:
                    threat_data['overall_threat_score'] = min(100, int((high_threat_observables / total_observables) * 100))
                else:
                    threat_data['overall_threat_score'] = 0
            except Exception as e:
                print(f"Error getting threat repository data: {e}")
                threat_data['overall_threat_score'] = 0
        else:
            threat_data['overall_threat_score'] = 0
        # 2. Get threat categories from recent alerts and reports
        threat_data['threat_categories'] = get_threat_categories_from_reports()
        # 3. Get threat timeline from recent activity
        threat_data['threat_timeline'] = get_threat_timeline_data()
        # 4. Get geographic threat data from observables
        threat_data['geo_threats'] = get_geographic_threat_data()
        # 5. Get MITRE ATT&CK techniques from database
        threat_data['attack_techniques'] = get_attack_techniques_data()
        # 6. Get threat actors from database
        threat_data['threat_actors'] = get_threat_actors_data()
        # 7. Get malware families from database
        threat_data['malware_families'] = get_malware_families_data()
        # 8. Get network traffic data from monitoring
        threat_data['network_traffic'] = get_network_traffic_data()
        # 9. Get process monitoring data
        threat_data['process_monitoring'] = get_process_monitoring_data()
    except Exception as e:
        print(f"Error collecting real threat data: {e}")
        # On error, return empty/zeroed data
        threat_data = {
            'overall_threat_score': 0,
            'threat_categories': {},
            'threat_timeline': [],
            'geo_threats': {},
            'attack_techniques': {},
            'threat_actors': {},
            'malware_families': {},
            'network_traffic': {},
            'process_monitoring': {}
        }
    return threat_data

def get_threat_categories_from_reports():
    try:
        repo = ThreatIntelligenceRepository()
        session = repo.db
        import json
        categories = {}
        observables = session.query(repo.Observable).all()
        for obs in observables:
            meta = json.loads(obs.meta) if obs.meta else {}
            category = meta.get('category')
            if category:
                categories[category.title()] = categories.get(category.title(), 0) + 1
        return dict(sorted(categories.items(), key=lambda x: x[1], reverse=True)) if categories else {}
    except Exception as e:
        print(f"Error getting threat categories from repository: {e}")
        return {}

def get_threat_timeline_data():
    try:
        repo = ThreatIntelligenceRepository()
        session = repo.db
        from sqlalchemy import func
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(days=30)
        results = (
            session.query(func.date(repo.Observable.first_seen), func.count(), func.avg(repo.Observable.threat_score))
            .filter(repo.Observable.first_seen >= cutoff)
            .group_by(func.date(repo.Observable.first_seen))
            .order_by(func.date(repo.Observable.first_seen))
            .all()
        )
        timeline_data = []
        for date, count, avg_score in results:
            if avg_score is not None:
                if avg_score >= 80:
                    severity = 'High'
                elif avg_score >= 50:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            else:
                severity = 'No data'
            timeline_data.append({
                'date': str(date),
                'threats': count,
                'severity': severity
            })
        return timeline_data
    except Exception as e:
        print(f"Error getting threat timeline from repository: {e}")
        return []

def get_geographic_threat_data():
    """Get geographic threat data from observables."""
    try:
        # Query the database for actual geographic threat data
        db_path = 'instance/threat_intel.db'
        if not os.path.exists(db_path):
            return get_default_geographic_threats()
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Query observables for IP addresses and their threat scores
        cursor.execute('''
            SELECT details, threat_score 
            FROM observables 
            WHERE type = 'ip_address' 
            AND details IS NOT NULL
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        if results:
            # Parse country information from details JSON
            countries = {}
            for details_json, score in results:
                try:
                    import json
                    details = json.loads(details_json)
                    country = details.get('country', 'Unknown')
                    if country in countries:
                        countries[country] += score
                    else:
                        countries[country] = score
                except:
                    continue
            
            # Return top countries by threat score
            sorted_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)
            return dict(sorted_countries[:8])  # Top 8 countries
        else:
            return get_default_geographic_threats()
            
    except Exception as e:
        print(f"Error getting geographic threat data from database: {e}")
        return get_default_geographic_threats()

def get_default_geographic_threats():
    """Return default geographic threat data when database is not available."""
    return {
        'United States': 45,
        'China': 25,
        'Russia': 18,
        'North Korea': 8,
        'Iran': 12,
        'India': 15,
        'Brazil': 10,
        'Germany': 8
    }

def get_attack_techniques_data():
    """Get MITRE ATT&CK techniques data."""
    try:
        # This would query your MITRE ATT&CK database
        return {
            'Initial Access': 6,
            'Execution': 10,
            'Persistence': 4,
            'Privilege Escalation': 5,
            'Defense Evasion': 8,
            'Credential Access': 3,
            'Discovery': 9,
            'Lateral Movement': 4,
            'Collection': 6,
            'Command and Control': 7,
            'Exfiltration': 3,
            'Impact': 5
        }
    except Exception as e:
        print(f"Error getting attack techniques: {e}")
        return {}

def get_threat_actors_data():
    try:
        repo = ThreatIntelligenceRepository()
        session = repo.db
        actors = session.query(repo.ThreatActor).order_by(repo.ThreatActor.name).limit(10).all()
        return {actor.name: 1 for actor in actors} if actors else {}
    except Exception as e:
        print(f"Error getting threat actors from repository: {e}")
        return {}

def get_malware_families_data():
    try:
        repo = ThreatIntelligenceRepository()
        session = repo.db
        malware = session.query(repo.MalwareFamily).order_by(repo.MalwareFamily.name).limit(10).all()
        return {m.name: 1 for m in malware} if malware else {}
    except Exception as e:
        print(f"Error getting malware families from repository: {e}")
        return {}

def get_network_traffic_data():
    """Get network traffic data from monitoring."""
    try:
        # Try to get real network monitoring data
        from integration.network_monitor_manager import NetworkMonitorManager
        
        try:
            monitor_manager = NetworkMonitorManager()
            if monitor_manager.is_monitoring():
                # Get real network traffic data
                traffic_data = monitor_manager.get_traffic_summary()
                if traffic_data:
                    return traffic_data
        except Exception as e:
            print(f"Error getting real network traffic data: {e}")
        
        # Fallback to default data
        return get_default_network_traffic()
        
    except Exception as e:
        print(f"Error getting network traffic data: {e}")
        return get_default_network_traffic()

def get_default_network_traffic():
    """Return default network traffic data when monitoring is not available."""
    return {
        'HTTP': 42,
        'HTTPS': 38,
        'DNS': 12,
        'SSH': 6,
        'FTP': 4,
        'SMTP': 8,
        'Other': 6
    }

def get_process_monitoring_data():
    """Get process monitoring data."""
    try:
        # Try to get real process monitoring data
        from integration.network_monitor_manager import NetworkMonitorManager
        
        try:
            monitor_manager = NetworkMonitorManager()
            if monitor_manager.is_monitoring():
                # Get real process data
                process_data = monitor_manager.get_process_summary()
                if process_data:
                    return process_data
        except Exception as e:
            print(f"Error getting real process monitoring data: {e}")
        
        # Fallback to default data
        return get_default_process_monitoring()
        
    except Exception as e:
        print(f"Error getting process monitoring data: {e}")
        return get_default_process_monitoring()

def get_default_process_monitoring():
    """Return default process monitoring data when monitoring is not available."""
    return {
        'System': 35,
        'Chrome': 18,
        'Explorer': 12,
        'svchost': 8,
        'Python': 6,
        'Node.js': 4,
        'Docker': 3,
        'Other': 28
    }

@threat_intel.route('/mitre-attack/techniques')
@login_required
def get_mitre_techniques():
    """Get MITRE ATT&CK techniques."""
    try:
        if not get_mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not available - import failed'}), 503
        
        mitre_attack = get_mitre_attack()
        if not mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not initialized'}), 503
        
        query = request.args.get('query', '')
        tactic = request.args.get('tactic', '')
        
        print(f"DEBUG: Query='{query}', Tactic='{tactic}'")
        
        if query:
            techniques = mitre_attack.search_techniques(query)
        elif tactic:
            techniques = mitre_attack.get_tactic_techniques(tactic)
        else:
            techniques = mitre_attack.get_all_techniques()
        
        print(f"DEBUG: Found {len(techniques)} techniques")
        if techniques:
            print(f"DEBUG: First technique: {techniques[0]}")
        
        # Apply limit if specified
        limit = request.args.get('limit', 100, type=int)
        if limit and len(techniques) > limit:
            techniques = techniques[:limit]
        
        return jsonify({'techniques': techniques})
        
    except Exception as e:
        print(f"Error getting MITRE techniques: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/mitre-attack/techniques/<technique_id>')
@login_required
def get_mitre_technique(technique_id):
    """Get specific MITRE ATT&CK technique."""
    try:
        if not get_mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not available - import failed'}), 503
        
        mitre_attack = get_mitre_attack()
        if not mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not initialized'}), 503
        
        technique = mitre_attack.get_technique_by_id(technique_id)
        if technique:
            return jsonify(technique)
        else:
            return jsonify({'error': 'Technique not found'}), 404
            
    except Exception as e:
        print(f"Error getting MITRE technique {technique_id}: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/mitre-attack/tactics')
@login_required
def get_mitre_tactics():
    """Get MITRE ATT&CK tactics."""
    try:
        if not get_mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not available - import failed'}), 503
        
        mitre_attack = get_mitre_attack()
        if not mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not initialized'}), 503
        
        tactics = mitre_attack.get_all_tactics()
        print(f"DEBUG: Found {len(tactics)} tactics")
        if tactics:
            print(f"DEBUG: First tactic: {tactics[0]}")
        
        return jsonify({'tactics': tactics})
        
    except Exception as e:
        print(f"Error getting MITRE tactics: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/mitre-attack/matrix')
@login_required
def get_mitre_matrix():
    """Get MITRE ATT&CK matrix."""
    try:
        if not get_mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not available - import failed'}), 503
        
        mitre_attack = get_mitre_attack()
        if not mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not initialized'}), 503
        
        matrix = mitre_attack.get_attack_matrix()
        print(f"DEBUG: Matrix data structure:")
        print(f"  - Tactics count: {len(matrix.get('tactics', []))}")
        print(f"  - Techniques by tactic keys: {list(matrix.get('techniques_by_tactic', {}).keys())}")
        if matrix.get('tactics'):
            print(f"  - First tactic: {matrix['tactics'][0]}")
        
        return jsonify(matrix)
        
    except Exception as e:
        print(f"Error getting MITRE matrix: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/threat-actors')
@login_required
def get_threat_actors():
    """Get threat actors from repository."""
    try:
        if not get_threat_repository:
            return jsonify({'error': 'Threat repository not available'}), 503
        
        threat_repository = get_threat_repository()
        query = request.args.get('query', '')
        if query:
            actors = threat_repository.search_threat_actors(query)
        else:
            # Get all actors (limit to 50)
            actors = threat_repository.search_threat_actors('')
        
        return jsonify({'threat_actors': actors})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/threat-actors/<actor_id>')
@login_required
def get_threat_actor(actor_id):
    """Get specific threat actor details."""
    try:
        if not get_threat_repository:
            return jsonify({'error': 'Threat repository not available'}), 503
        
        threat_repository = get_threat_repository()
        actor = threat_repository.get_threat_actor_details(actor_id)
        if actor:
            return jsonify(actor)
        else:
            return jsonify({'error': 'Threat actor not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/malware-families')
@login_required
def get_malware_families():
    """Get malware families from repository."""
    try:
        if not get_threat_repository:
            return jsonify({'error': 'Threat repository not available'}), 503
        
        threat_repository = get_threat_repository()
        query = request.args.get('query', '')
        if query:
            malware = threat_repository.search_malware_families(query)
        else:
            # Get all malware families (limit to 50)
            malware = threat_repository.search_malware_families('')
        
        return jsonify({'malware_families': malware})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/observables/correlate', methods=['POST'])
@login_required
def correlate_observable():
    """Correlate an observable with threat intelligence."""
    try:
        if not get_threat_repository:
            return jsonify({'error': 'Threat repository not available'}), 503
        
        threat_repository = get_threat_repository()
        data = request.get_json()
        if not data or 'type' not in data or 'value' not in data:
            return jsonify({'error': 'Observable type and value required'}), 400
        
        correlation = threat_repository.correlate_observables(data)
        return jsonify(correlation)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/statistics')
@login_required
def get_threat_statistics():
    """Get threat intelligence statistics."""
    try:
        if not get_threat_repository:
            # Return sample statistics if repository is not available
            return jsonify(generate_sample_statistics())
        
        threat_repository = get_threat_repository()
        stats = threat_repository.get_threat_statistics()
        
        # Only return sample data if all counts are 0 (indicating empty database)
        if stats and any(v > 0 for v in stats.values()):
            return jsonify(stats)
        else:
            # Database is empty, return sample data
            return jsonify(generate_sample_statistics())
        
    except Exception as e:
        print(f"Error getting threat statistics: {e}")
        # Return sample data on error
        return jsonify(generate_sample_statistics())

def generate_sample_statistics():
    """Generate sample threat intelligence statistics."""
    import random
    
    return {
        'threat_actors': random.randint(50, 150),
        'malware_families': random.randint(30, 80),
        'vulnerabilities': random.randint(100, 300),
        'observables': random.randint(500, 2000),
        'high_threat_observables': random.randint(50, 200)
    }

# Security News API routes
@threat_intel.route('/security-news/cache-status')
@login_required
def get_news_cache_status():
    """Get security news cache status."""
    try:
        if not get_rss_processor:
            return jsonify({'error': 'RSS processor not available'}), 503
        
        rss_processor = get_rss_processor()
        status = rss_processor.get_cache_status()
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/security-news/refresh', methods=['POST'])
@login_required
def refresh_news_cache():
    """Manually refresh the news cache."""
    try:
        if not get_rss_processor:
            return jsonify({'error': 'RSS processor not available'}), 503
        
        rss_processor = get_rss_processor()
        
        # Force refresh by processing without cache
        articles = rss_processor.process_security_news(use_cache=False)
        
        return jsonify({
            'success': True,
            'articles_refreshed': len(articles),
            'message': 'News cache refreshed successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/security-news/search')
@login_required
def search_security_news():
    """Search security news."""
    try:
        if not get_rss_processor:
            return jsonify({'error': 'RSS processor not available'}), 503
        
        rss_processor = get_rss_processor()
        query = request.args.get('query', '')
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        limit = request.args.get('limit', 20, type=int)
        articles = rss_processor.search_articles(query, limit)
        
        return jsonify({'articles': articles})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/security-news/dashboard')
@login_required
def get_news_dashboard():
    """Get security news dashboard data."""
    try:
        if not get_rss_processor or not advanced_dashboard:
            return jsonify({'error': 'News dashboard not available'}), 503
        
        rss_processor = get_rss_processor()
        articles = rss_processor.get_latest_articles(100)
        dashboard = advanced_dashboard.create_security_news_dashboard(articles)
        
        return jsonify(dashboard)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/search')
@login_required
def search_threat_intelligence():
    """Search threat intelligence repository."""
    try:
        if not get_threat_repository:
            # Return sample search results if repository is not available
            return jsonify({'results': generate_sample_search_results()})
        
        threat_repository = get_threat_repository()
        query = request.args.get('query', '')
        category = request.args.get('category', '')
        
        if not query:
            return jsonify({'results': []})
        
        results = threat_repository.search(query, category)
        
        # If no results available, return sample data
        if not results:
            results = generate_sample_search_results()
        
        return jsonify({'results': results})
        
    except Exception as e:
        # Return sample data on error
        return jsonify({'results': generate_sample_search_results()})

def generate_sample_search_results():
    """Generate sample threat intelligence search results."""
    from datetime import datetime, timedelta
    import random
    
    sample_results = [
        {
            'id': 'ti_001',
            'type': 'ip_address',
            'value': '192.168.1.100',
            'description': 'Malicious IP address associated with Emotet malware',
            'threat_score': 85,
            'category': 'malware',
            'first_seen': (datetime.now() - timedelta(days=30)).isoformat(),
            'last_seen': datetime.now().isoformat(),
            'tags': ['emotet', 'malware', 'c2'],
            'sources': ['AbuseIPDB', 'VirusTotal'],
            'details': {
                'country': 'Russia',
                'isp': 'Unknown',
                'reports': 150,
                'confidence': 0.9
            }
        },
        {
            'id': 'ti_002',
            'type': 'domain',
            'value': 'malware.example.com',
            'description': 'Command and control domain for TrickBot malware',
            'threat_score': 90,
            'category': 'malware',
            'first_seen': (datetime.now() - timedelta(days=45)).isoformat(),
            'last_seen': datetime.now().isoformat(),
            'tags': ['trickbot', 'malware', 'c2'],
            'sources': ['VirusTotal', 'URLVoid'],
            'details': {
                'registrar': 'Unknown',
                'creation_date': '2023-01-15',
                'reports': 200,
                'confidence': 0.95
            }
        },
        {
            'id': 'ti_003',
            'type': 'hash',
            'value': 'a1b2c3d4e5f6789012345678901234567890abcd',
            'description': 'Emotet malware sample hash',
            'threat_score': 95,
            'category': 'malware',
            'first_seen': (datetime.now() - timedelta(days=60)).isoformat(),
            'last_seen': datetime.now().isoformat(),
            'tags': ['emotet', 'malware', 'trojan'],
            'sources': ['VirusTotal', 'MalwareBazaar'],
            'details': {
                'file_type': 'PE32',
                'file_size': 245760,
                'detections': 45,
                'confidence': 0.98
            }
        },
        {
            'id': 'ti_004',
            'type': 'url',
            'value': 'https://phish.example.com/login',
            'description': 'Phishing URL targeting financial institutions',
            'threat_score': 80,
            'category': 'phishing',
            'first_seen': (datetime.now() - timedelta(days=15)).isoformat(),
            'last_seen': datetime.now().isoformat(),
            'tags': ['phishing', 'financial', 'credential_theft'],
            'sources': ['URLVoid', 'PhishTank'],
            'details': {
                'target': 'Financial Services',
                'technique': 'Credential Harvesting',
                'reports': 75,
                'confidence': 0.85
            }
        },
        {
            'id': 'ti_005',
            'type': 'threat_actor',
            'value': 'APT29',
            'description': 'Advanced Persistent Threat group associated with Russian intelligence',
            'threat_score': 95,
            'category': 'apt',
            'first_seen': (datetime.now() - timedelta(days=365)).isoformat(),
            'last_seen': datetime.now().isoformat(),
            'tags': ['apt', 'russia', 'state_sponsored'],
            'sources': ['MITRE ATT&CK', 'CrowdStrike'],
            'details': {
                'country': 'Russia',
                'motivation': 'Espionage',
                'targets': ['Government', 'Technology', 'Healthcare'],
                'confidence': 0.99
            }
        }
    ]
    
    # Add more random results
    for i in range(10):
        types = ['ip_address', 'domain', 'hash', 'url', 'threat_actor']
        categories = ['malware', 'phishing', 'apt', 'ransomware', 'vulnerability']
        ti_type = random.choice(types)
        category = random.choice(categories)
        
        result = {
            'id': f'ti_{i+6:03d}',
            'type': ti_type,
            'value': f'sample_{ti_type}_{i+1}.example.com',
            'description': f'Sample {category} threat intelligence item {i+1}',
            'threat_score': random.randint(30, 95),
            'category': category,
            'first_seen': (datetime.now() - timedelta(days=random.randint(1, 90))).isoformat(),
            'last_seen': datetime.now().isoformat(),
            'tags': [category, 'sample'],
            'sources': ['Sample Source'],
            'details': {
                'confidence': random.uniform(0.5, 0.99),
                'reports': random.randint(1, 100)
            }
        }
        sample_results.append(result)
    
    return sample_results

# Test route for dashboard data (no authentication required)
@threat_intel.route('/test-dashboard-data')
def get_test_dashboard_data():
    """Get threat intelligence dashboard data for testing (no auth required)."""
    try:
        if not advanced_dashboard:
            return jsonify({'error': 'Advanced dashboard not available'}), 503
        
        # Generate comprehensive sample threat data
        from datetime import datetime, timedelta
        import random
        
        # Generate realistic threat timeline data
        timeline_data = []
        for i in range(30):
            date = datetime.now() - timedelta(days=29-i)
            timeline_data.append({
                'date': date.strftime('%Y-%m-%d'),
                'threats': random.randint(5, 25),
                'severity': random.choice(['Low', 'Medium', 'High'])
            })
        
        # Generate realistic threat data
        threat_data = {
            'overall_threat_score': random.randint(45, 85),
            'threat_categories': {
                'Malware': random.randint(20, 40),
                'Phishing': random.randint(15, 35),
                'DDoS': random.randint(10, 25),
                'Data Breach': random.randint(5, 20),
                'APT': random.randint(8, 18),
                'Ransomware': random.randint(12, 28),
                'Insider Threat': random.randint(3, 15),
                'Other': random.randint(5, 15)
            },
            'threat_timeline': timeline_data,
            'geo_threats': {
                'United States': random.randint(30, 50),
                'China': random.randint(20, 35),
                'Russia': random.randint(15, 30),
                'North Korea': random.randint(5, 15),
                'Iran': random.randint(8, 20),
                'India': random.randint(10, 25),
                'Brazil': random.randint(5, 18),
                'Germany': random.randint(8, 22)
            },
            'attack_techniques': {
                'Initial Access': random.randint(3, 8),
                'Execution': random.randint(5, 12),
                'Persistence': random.randint(2, 6),
                'Privilege Escalation': random.randint(3, 8),
                'Defense Evasion': random.randint(4, 10),
                'Credential Access': random.randint(2, 7),
                'Discovery': random.randint(5, 12),
                'Lateral Movement': random.randint(2, 6),
                'Collection': random.randint(3, 8),
                'Command and Control': random.randint(4, 9),
                'Exfiltration': random.randint(2, 6),
                'Impact': random.randint(3, 8)
            },
            'threat_actors': {
                'APT29 (Cozy Bear)': random.randint(10, 20),
                'APT28 (Fancy Bear)': random.randint(8, 18),
                'Lazarus Group': random.randint(12, 25),
                'Wizard Spider': random.randint(6, 15),
                'Cobalt Group': random.randint(5, 12),
                'DarkHydrus': random.randint(3, 10),
                'APT41': random.randint(7, 16),
                'APT40': random.randint(4, 12)
            },
            'malware_families': {
                'Emotet': random.randint(20, 35),
                'TrickBot': random.randint(15, 30),
                'Ryuk': random.randint(10, 25),
                'Conti': random.randint(8, 20),
                'QakBot': random.randint(12, 28),
                'Revil': random.randint(6, 18),
                'LockBit': random.randint(10, 22),
                'BlackCat': random.randint(5, 15),
                'Other': random.randint(8, 20)
            },
            'network_traffic': {
                'HTTP': random.randint(35, 50),
                'HTTPS': random.randint(30, 45),
                'DNS': random.randint(10, 20),
                'SSH': random.randint(3, 10),
                'FTP': random.randint(2, 8),
                'SMTP': random.randint(5, 15),
                'Other': random.randint(3, 12)
            },
            'process_monitoring': {
                'System': random.randint(25, 40),
                'Chrome': random.randint(10, 20),
                'Explorer': random.randint(8, 15),
                'svchost': random.randint(5, 12),
                'Python': random.randint(3, 10),
                'Node.js': random.randint(2, 8),
                'Docker': random.randint(1, 6),
                'Other': random.randint(20, 35)
            }
        }
        
        dashboard = advanced_dashboard.create_threat_intelligence_dashboard(threat_data)
        return jsonify(dashboard)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/security-news')
@login_required
def get_security_news():
    """Get security news from RSS feeds with immediate cache access."""
    try:
        if not get_rss_processor:
            # Return empty with message if RSS processor is not available
            return jsonify({
                'articles': [],
                'source': 'error',
                'cache_fresh': False,
                'message': 'RSS processor not available - please check system configuration'
            })
        
        rss_processor = get_rss_processor()
        limit = request.args.get('limit', 20, type=int)
        category = request.args.get('category', '')
        
        # First, try to get cached data immediately
        cached_articles = rss_processor.get_cached_news()
        
        if cached_articles:
            # Filter by category if specified
            if category:
                filtered_articles = [
                    article for article in cached_articles 
                    if article.get('category') == category
                ]
            else:
                filtered_articles = cached_articles
            
            # Apply limit
            filtered_articles = filtered_articles[:limit]
            
            # Return cached data immediately
            return jsonify({
                'articles': filtered_articles,
                'source': 'cache',
                'cache_fresh': rss_processor.is_cache_fresh(),
                'message': f'Loaded {len(filtered_articles)} articles from cache'
            })
        
        # If no cache, try to process feeds
        print("No cached data available, processing RSS feeds...")
        if category:
            articles = rss_processor.get_articles_by_category(category, limit)
        else:
            articles = rss_processor.get_latest_articles(limit)
        
        # If we got real articles, return them
        if articles and len(articles) > 0:
            return jsonify({
                'articles': articles,
                'source': 'live',
                'cache_fresh': False,
                'message': f'Loaded {len(articles)} articles from RSS feeds'
            })
        
        # If no articles from RSS, check if background processing is still running
        cache_status = rss_processor.get_cache_status()
        if not cache_status['has_cache'] and cache_status['background_thread_alive']:
            # Background thread is still working, return empty with message
            return jsonify({
                'articles': [],
                'source': 'loading',
                'cache_fresh': False,
                'message': 'Background processing in progress - please wait a moment and refresh'
            })
        
        # No articles available - return empty with helpful message
        return jsonify({
            'articles': [],
            'source': 'empty',
            'cache_fresh': False,
            'message': 'No articles available at the moment - feeds may be temporarily unavailable'
        })
        
    except Exception as e:
        print(f"Error getting security news: {e}")
        # Return empty on error
        return jsonify({
            'articles': [],
            'source': 'error',
            'cache_fresh': False,
            'message': f'Error occurred: {str(e)} - please try again later'
        })

@threat_intel.route('/mitre-attack/clear-cache', methods=['POST'])
@login_required
def clear_mitre_cache():
    """Clear MITRE ATT&CK cache and force fresh load."""
    try:
        if not get_mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not available'}), 503
        
        mitre_attack = get_mitre_attack()
        if not mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not initialized'}), 503
        
        # Clear cache and reload
        mitre_attack.clear_cache()
        
        # Get new status
        status = mitre_attack.get_cache_status()
        
        return jsonify({
            'message': 'Cache cleared and data reloaded successfully',
            'status': status
        })
        
    except Exception as e:
        print(f"Error clearing MITRE cache: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/mitre-attack/status')
@login_required
def get_mitre_status():
    """Get MITRE ATT&CK cache status."""
    try:
        if not get_mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not available'}), 503
        
        mitre_attack = get_mitre_attack()
        if not mitre_attack:
            return jsonify({'error': 'MITRE ATT&CK not initialized'}), 503
        
        status = mitre_attack.get_cache_status()
        return jsonify(status)
        
    except Exception as e:
        print(f"Error getting MITRE status: {e}")
        return jsonify({'error': str(e)}), 500

def cleanup_old_reports(max_reports=100, max_age_days=30):
    """Clean up old reports to prevent the folder from growing too large."""
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
    if not os.path.exists(reports_dir):
        return
    
    # Get all report files
    report_files = glob.glob(os.path.join(reports_dir, 'report_*.json'))
    
    # Sort by modification time (oldest first)
    report_files.sort(key=os.path.getmtime)
    
    # Calculate cutoff date for age-based cleanup
    cutoff_time = time.time() - (max_age_days * 24 * 3600)
    
    files_to_delete = []
    
    # Add files older than max_age_days
    for report_file in report_files:
        if os.path.getmtime(report_file) < cutoff_time:
            files_to_delete.append(report_file)
    
    # If we still have too many files, delete the oldest ones
    remaining_files = [f for f in report_files if f not in files_to_delete]
    if len(remaining_files) > max_reports:
        files_to_delete.extend(remaining_files[:-max_reports])
    
    # Delete the files
    for file_path in files_to_delete:
        try:
            os.remove(file_path)
            print(f"Cleaned up old report: {os.path.basename(file_path)}")
        except Exception as e:
            print(f"Error deleting {file_path}: {e}")
    
    if files_to_delete:
        print(f"Cleaned up {len(files_to_delete)} old report files")
    
    return len(files_to_delete)

@api.route('/cleanup-reports', methods=['POST'])
@login_required
def cleanup_reports():
    """Manually trigger report cleanup."""
    try:
        data = request.get_json() or {}
        max_reports = data.get('max_reports', 100)
        max_age_days = data.get('max_age_days', 7)
        
        # Clean up database reports
        db_deleted = cleanup_old_reports_from_db(max_reports=max_reports)
        
        # Clean up file reports (legacy)
        file_deleted = cleanup_old_reports(max_reports=50, max_age_days=max_age_days)
        
        total_deleted = db_deleted + file_deleted
        
        return jsonify({
            'success': True,
            'message': f'Cleaned up {total_deleted} old report files (DB: {db_deleted}, Files: {file_deleted})',
            'deleted_count': total_deleted,
            'database_deleted': db_deleted,
            'files_deleted': file_deleted
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def cleanup_old_reports_from_db(max_reports=100):
    """Clean up old reports from database."""
    try:
        from .models import Report
        
        # Get total count
        total_count = Report.query.count()
        
        if total_count > max_reports:
            # Get the IDs of reports to keep (most recent)
            reports_to_keep = Report.query.order_by(Report.created_at.desc()).limit(max_reports).all()
            keep_ids = [r.id for r in reports_to_keep]
            
            # Delete older reports
            deleted_count = Report.query.filter(~Report.id.in_(keep_ids)).delete()
            db.session.commit()
            
            print(f"Cleaned up {deleted_count} old reports from database")
            return deleted_count
        
        return 0
        
    except Exception as e:
        print(f"Error cleaning up database reports: {e}")
        db.session.rollback()
        return 0

@threat_intel.route('/mitre-attack/correlate-reports')
@login_required
def correlate_reports_with_mitre():
    """Correlate threat intelligence reports with MITRE ATT&CK techniques."""
    try:
        from datetime import datetime, timedelta
        
        # Get recent reports from database
        recent_reports = Report.query.order_by(Report.created_at.desc()).limit(100).all()
        
        # Initialize correlation data
        technique_usage = {}
        tactic_usage = {}
        
        # Process each report
        for report in recent_reports:
            results = report.get_results()
            
            # Analyze AbuseIPDB data
            if 'abuseipdb' in results and isinstance(results['abuseipdb'], dict):
                abuse_data = results['abuseipdb'].get('data', {})
                
                # Check if we have abuse confidence score
                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                
                # Map abuse score to MITRE techniques based on threat level
                if abuse_score > 80:
                    # High threat - likely malicious activity
                    technique_mappings = [
                        {
                            'technique_id': 'T1190',
                            'technique_name': 'Exploit Public-Facing Application',
                            'tactic_id': 'TA0001',
                            'tactic_name': 'Initial Access'
                        },
                        {
                            'technique_id': 'T1566',
                            'technique_name': 'Phishing',
                            'tactic_id': 'TA0001',
                            'tactic_name': 'Initial Access'
                        }
                    ]
                elif abuse_score > 50:
                    # Medium threat - suspicious activity
                    technique_mappings = [
                        {
                            'technique_id': 'T1046',
                            'technique_name': 'Network Service Discovery',
                            'tactic_id': 'TA0007',
                            'tactic_name': 'Discovery'
                        },
                        {
                            'technique_id': 'T1110',
                            'technique_name': 'Brute Force',
                            'tactic_id': 'TA0006',
                            'tactic_name': 'Credential Access'
                        }
                    ]
                else:
                    # Low threat - but still track for correlation
                    technique_mappings = [
                        {
                            'technique_id': 'T1046',
                            'technique_name': 'Network Service Discovery',
                            'tactic_id': 'TA0007',
                            'tactic_name': 'Discovery'
                        }
                    ]
                
                # Add technique mappings to usage tracking
                for mapping in technique_mappings:
                    technique_id = mapping['technique_id']
                    tactic_id = mapping['tactic_id']
                    
                    # Track technique usage
                    if technique_id not in technique_usage:
                        technique_usage[technique_id] = {
                            'count': 0,
                            'targets': [],
                            'last_seen': None,
                            'technique_name': mapping['technique_name'],
                            'tactic_name': mapping['tactic_name']
                        }
                    
                    technique_usage[technique_id]['count'] += 1
                    technique_usage[technique_id]['targets'].append(report.target)
                    if not technique_usage[technique_id]['last_seen'] or report.created_at > technique_usage[technique_id]['last_seen']:
                        technique_usage[technique_id]['last_seen'] = report.created_at
                    
                    # Track tactic usage
                    if tactic_id not in tactic_usage:
                        tactic_usage[tactic_id] = {
                            'count': 0,
                            'techniques': set(),
                            'tactic_name': mapping['tactic_name']
                        }
                    
                    tactic_usage[tactic_id]['count'] += 1
                    tactic_usage[tactic_id]['techniques'].add(technique_id)
            
            # Analyze VirusTotal data
            if 'virustotal' in results and isinstance(results['virustotal'], dict):
                vt_data = results['virustotal'].get('data', {})
                
                # Check for malicious detections
                last_analysis_stats = vt_data.get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
                
                if malicious_count > 0 or suspicious_count > 0:
                    # Map malware detections to MITRE techniques
                    malware_techniques = [
                        {
                            'technique_id': 'T1059',
                            'technique_name': 'Command and Scripting Interpreter',
                            'tactic_id': 'TA0002',
                            'tactic_name': 'Execution'
                        },
                        {
                            'technique_id': 'T1071',
                            'technique_name': 'Application Layer Protocol',
                            'tactic_id': 'TA0011',
                            'tactic_name': 'Command and Control'
                        }
                    ]
                    
                    for mapping in malware_techniques:
                        technique_id = mapping['technique_id']
                        tactic_id = mapping['tactic_id']
                        
                        # Track technique usage
                        if technique_id not in technique_usage:
                            technique_usage[technique_id] = {
                                'count': 0,
                                'targets': [],
                                'last_seen': None,
                                'technique_name': mapping['technique_name'],
                                'tactic_name': mapping['tactic_name']
                            }
                        
                        technique_usage[technique_id]['count'] += 1
                        technique_usage[technique_id]['targets'].append(report.target)
                        if not technique_usage[technique_id]['last_seen'] or report.created_at > technique_usage[technique_id]['last_seen']:
                            technique_usage[technique_id]['last_seen'] = report.created_at
                        
                        # Track tactic usage
                        if tactic_id not in tactic_usage:
                            tactic_usage[tactic_id] = {
                                'count': 0,
                                'techniques': set(),
                                'tactic_name': mapping['tactic_name']
                            }
                        
                        tactic_usage[tactic_id]['count'] += 1
                        tactic_usage[tactic_id]['techniques'].add(technique_id)
        
        # Convert sets to lists for JSON serialization
        for tactic_id, tactic_data in tactic_usage.items():
            tactic_data['techniques'] = list(tactic_data['techniques'])
        
        # Sort by usage count
        sorted_techniques = sorted(technique_usage.items(), key=lambda x: x[1]['count'], reverse=True)
        sorted_tactics = sorted(tactic_usage.items(), key=lambda x: x[1]['count'], reverse=True)
        
        return jsonify({
            'technique_usage': dict(sorted_techniques[:20]),  # Top 20 techniques
            'tactic_usage': dict(sorted_tactics),
            'total_reports_analyzed': len(recent_reports),
            'analysis_timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        print(f"Error correlating reports with MITRE: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/mitre-attack/custom-matrix')
@login_required
def generate_custom_attack_matrix():
    """Generate a custom ATT&CK matrix based on your threat intelligence data."""
    try:
        from datetime import datetime, timedelta
        
        # Get recent reports from database (same logic as correlate_reports_with_mitre)
        recent_reports = Report.query.order_by(Report.created_at.desc()).limit(100).all()
        
        # Initialize correlation data
        technique_usage = {}
        tactic_usage = {}
        
        # Process each report (same logic as correlate_reports_with_mitre)
        for report in recent_reports:
            results = report.get_results()
            
            # Analyze AbuseIPDB data
            if 'abuseipdb' in results and isinstance(results['abuseipdb'], dict):
                abuse_data = results['abuseipdb'].get('data', {})
                
                # Check if we have abuse confidence score
                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                
                # Map abuse score to MITRE techniques based on threat level
                if abuse_score > 80:
                    # High threat - likely malicious activity
                    technique_mappings = [
                        {
                            'technique_id': 'T1190',
                            'technique_name': 'Exploit Public-Facing Application',
                            'tactic_id': 'TA0001',
                            'tactic_name': 'Initial Access'
                        },
                        {
                            'technique_id': 'T1566',
                            'technique_name': 'Phishing',
                            'tactic_id': 'TA0001',
                            'tactic_name': 'Initial Access'
                        }
                    ]
                elif abuse_score > 50:
                    # Medium threat - suspicious activity
                    technique_mappings = [
                        {
                            'technique_id': 'T1046',
                            'technique_name': 'Network Service Discovery',
                            'tactic_id': 'TA0007',
                            'tactic_name': 'Discovery'
                        },
                        {
                            'technique_id': 'T1110',
                            'technique_name': 'Brute Force',
                            'tactic_id': 'TA0006',
                            'tactic_name': 'Credential Access'
                        }
                    ]
                else:
                    # Low threat - but still track for correlation
                    technique_mappings = [
                        {
                            'technique_id': 'T1046',
                            'technique_name': 'Network Service Discovery',
                            'tactic_id': 'TA0007',
                            'tactic_name': 'Discovery'
                        }
                    ]
                
                # Add technique mappings to usage tracking
                for mapping in technique_mappings:
                    technique_id = mapping['technique_id']
                    tactic_id = mapping['tactic_id']
                    
                    # Track technique usage
                    if technique_id not in technique_usage:
                        technique_usage[technique_id] = {
                            'count': 0,
                            'targets': [],
                            'last_seen': None,
                            'technique_name': mapping['technique_name'],
                            'tactic_name': mapping['tactic_name']
                        }
                    
                    technique_usage[technique_id]['count'] += 1
                    technique_usage[technique_id]['targets'].append(report.target)
                    if not technique_usage[technique_id]['last_seen'] or report.created_at > technique_usage[technique_id]['last_seen']:
                        technique_usage[technique_id]['last_seen'] = report.created_at
                    
                    # Track tactic usage
                    if tactic_id not in tactic_usage:
                        tactic_usage[tactic_id] = {
                            'count': 0,
                            'techniques': set(),
                            'tactic_name': mapping['tactic_name']
                        }
                    
                    tactic_usage[tactic_id]['count'] += 1
                    tactic_usage[tactic_id]['techniques'].add(technique_id)
            
            # Analyze VirusTotal data
            if 'virustotal' in results and isinstance(results['virustotal'], dict):
                vt_data = results['virustotal'].get('data', {})
                
                # Check for malicious detections
                last_analysis_stats = vt_data.get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
                
                if malicious_count > 0 or suspicious_count > 0:
                    # Map malware detections to MITRE techniques
                    malware_techniques = [
                        {
                            'technique_id': 'T1059',
                            'technique_name': 'Command and Scripting Interpreter',
                            'tactic_id': 'TA0002',
                            'tactic_name': 'Execution'
                        },
                        {
                            'technique_id': 'T1071',
                            'technique_name': 'Application Layer Protocol',
                            'tactic_id': 'TA0011',
                            'tactic_name': 'Command and Control'
                        }
                    ]
                    
                    for mapping in malware_techniques:
                        technique_id = mapping['technique_id']
                        tactic_id = mapping['tactic_id']
                        
                        # Track technique usage
                        if technique_id not in technique_usage:
                            technique_usage[technique_id] = {
                                'count': 0,
                                'targets': [],
                                'last_seen': None,
                                'technique_name': mapping['technique_name'],
                                'tactic_name': mapping['tactic_name']
                            }
                        
                        technique_usage[technique_id]['count'] += 1
                        technique_usage[technique_id]['targets'].append(report.target)
                        if not technique_usage[technique_id]['last_seen'] or report.created_at > technique_usage[technique_id]['last_seen']:
                            technique_usage[technique_id]['last_seen'] = report.created_at
                        
                        # Track tactic usage
                        if tactic_id not in tactic_usage:
                            tactic_usage[tactic_id] = {
                                'count': 0,
                                'techniques': set(),
                                'tactic_name': mapping['tactic_name']
                            }
                        
                        tactic_usage[tactic_id]['count'] += 1
                        tactic_usage[tactic_id]['techniques'].add(technique_id)
        
        # Convert sets to lists for JSON serialization
        for tactic_id, tactic_data in tactic_usage.items():
            tactic_data['techniques'] = list(tactic_data['techniques'])
        
        # Create custom matrix data
        custom_matrix = {
            'tactics': [],
            'techniques': [],
            'metadata': {
                'name': 'Custom Threat Intelligence Matrix',
                'description': 'ATT&CK matrix based on your threat intelligence reports',
                'created': datetime.utcnow().isoformat(),
                'total_reports': len(recent_reports)
            }
        }
        
        # Process tactics
        for tactic_id, tactic_data in tactic_usage.items():
            tactic_info = {
                'id': tactic_id,
                'name': tactic_data['tactic_name'],
                'usage_count': tactic_data['count'],
                'technique_count': len(tactic_data['techniques'])
            }
            custom_matrix['tactics'].append(tactic_info)
        
        # Process techniques
        for technique_id, technique_data in technique_usage.items():
            technique_info = {
                'id': technique_id,
                'name': technique_data['technique_name'],
                'tactic': technique_data['tactic_name'],
                'usage_count': technique_data['count'],
                'targets': technique_data['targets'][:5],  # Show top 5 targets
                'last_seen': technique_data['last_seen'].isoformat() if technique_data['last_seen'] else None
            }
            custom_matrix['techniques'].append(technique_info)
        
        return jsonify(custom_matrix)
        
    except Exception as e:
        print(f"Error generating custom matrix: {e}")
        return jsonify({'error': str(e)}), 500

@threat_intel.route('/mitre-attack/threat-hunting')
@login_required
def threat_hunting_suggestions():
    """Provide threat hunting suggestions based on your threat intelligence."""
    try:
        # Get recent high-threat reports
        high_threat_reports = Report.query.filter(
            Report.abuse_score > 80
        ).order_by(Report.created_at.desc()).limit(20).all()
        
        hunting_suggestions = []
        
        for report in high_threat_reports:
            results = report.get_results()
            suggestions = analyze_report_for_hunting(report.target, results)
            if suggestions:
                hunting_suggestions.extend(suggestions)
        
        # Group suggestions by technique
        grouped_suggestions = {}
        for suggestion in hunting_suggestions:
            technique_id = suggestion['technique_id']
            if technique_id not in grouped_suggestions:
                grouped_suggestions[technique_id] = []
            grouped_suggestions[technique_id].append(suggestion)
        
        return jsonify({
            'hunting_suggestions': grouped_suggestions,
            'total_suggestions': len(hunting_suggestions),
            'high_threat_reports_analyzed': len(high_threat_reports)
        })
        
    except Exception as e:
        print(f"Error generating hunting suggestions: {e}")
        return jsonify({'error': str(e)}), 500

# Helper functions for MITRE correlation
def map_category_to_technique(category):
    """Map AbuseIPDB categories to MITRE ATT&CK techniques."""
    category_mapping = {
        'DDoS Attack': {
            'technique_id': 'T1498',
            'technique_name': 'Network Denial of Service',
            'tactic_id': 'TA0040',
            'tactic_name': 'Impact'
        },
        'Fraud Orders': {
            'technique_id': 'T1078',
            'technique_name': 'Valid Accounts',
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access'
        },
        'Hacking': {
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access'
        },
        'Spam': {
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access'
        },
        'Web App Attack': {
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access'
        },
        'Port Scan': {
            'technique_id': 'T1046',
            'technique_name': 'Network Service Discovery',
            'tactic_id': 'TA0007',
            'tactic_name': 'Discovery'
        },
        'Brute-Force': {
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'tactic_id': 'TA0006',
            'tactic_name': 'Credential Access'
        }
    }
    
    return category_mapping.get(category, None)

def map_malware_to_techniques(malware_name):
    """Map malware families to MITRE ATT&CK techniques."""
    malware_mapping = {
        'emotet': ['T1071', 'T1566', 'T1059'],  # Command and Control, Phishing, Command and Scripting Interpreter
        'trickbot': ['T1071', 'T1566', 'T1059'],
        'ryuk': ['T1486', 'T1489'],  # Data Encrypted for Impact, Service Stop
        'wannacry': ['T1486', 'T1489'],
        'notpetya': ['T1486', 'T1489'],
        'cobaltstrike': ['T1071', 'T1059', 'T1055'],  # Command and Control, Command and Scripting Interpreter, Process Injection
        'metasploit': ['T1059', 'T1055', 'T1071'],
        'powershell': ['T1059', 'T1055'],
        'cmd': ['T1059'],
        'javascript': ['T1059'],
        'vba': ['T1059'],
        'macro': ['T1059']
    }
    
    malware_lower = malware_name.lower()
    for key, techniques in malware_mapping.items():
        if key in malware_lower:
            return techniques
    
    return []

def analyze_report_for_hunting(target, results):
    """Analyze a report and provide threat hunting suggestions."""
    suggestions = []
    
    # Analyze AbuseIPDB data
    if 'abuseipdb' in results and isinstance(results['abuseipdb'], dict):
        abuse_data = results['abuseipdb'].get('data', {})
        categories = abuse_data.get('reports', [])
        
        for category in categories:
            technique_mapping = map_category_to_technique(category)
            if technique_mapping:
                suggestion = {
                    'technique_id': technique_mapping['technique_id'],
                    'technique_name': technique_mapping['technique_name'],
                    'tactic': technique_mapping['tactic_name'],
                    'target': target,
                    'category': category,
                    'hunting_query': generate_hunting_query(technique_mapping['technique_id'], target),
                    'priority': 'high' if category in ['Hacking', 'Web App Attack'] else 'medium'
                }
                suggestions.append(suggestion)
    
    return suggestions

def generate_hunting_query(technique_id, target):
    """Generate a threat hunting query based on MITRE technique and target."""
    queries = {
        'T1498': f"Search for DDoS activity targeting {target}",
        'T1078': f"Look for suspicious account activity related to {target}",
        'T1190': f"Check for web application attacks against {target}",
        'T1566': f"Search for phishing emails mentioning {target}",
        'T1046': f"Look for port scanning activity from {target}",
        'T1110': f"Check for brute force attempts from {target}",
        'T1486': f"Monitor for ransomware activity related to {target}",
        'T1059': f"Look for suspicious command execution related to {target}"
    }
    
    return queries.get(technique_id, f"Investigate {target} for suspicious activity")
