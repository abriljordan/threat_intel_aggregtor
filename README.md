# 🛡️ Threat Intelligence Aggregator with Network Monitoring

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.1.1-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-In%20Development-orange.svg)]()

A comprehensive security monitoring solution that combines external threat intelligence with real-time local network monitoring. The application provides a unified web dashboard for threat intelligence analysis and local security monitoring.

## 🚀 Features

### 🔍 Threat Intelligence
- **Multi-source Integration**: AbuseIPDB, VirusTotal, Shodan, and HttpBL
- **IP Reputation Checking**: Real-time IP reputation analysis
- **Malware Detection**: File hash analysis and malware scanning
- **Network Intelligence**: Port scanning and service detection
- **MITRE ATT&CK Integration**: Threat correlation with MITRE framework

### 🌐 Network Monitoring
- **Real-time Connection Tracking**: Monitor all network connections
- **Process Monitoring**: Track system processes and their network activity
- **YARA-based Malware Detection**: Local malware scanning using YARA rules
- **Threat Correlation**: Automatically correlate local events with external threat intelligence

### 📊 Unified Dashboard
- **Interactive Web Interface**: Real-time updates via WebSocket
- **Comprehensive Alerts**: Combined alerts from local and external sources
- **Risk Scoring**: Intelligent threat scoring based on multiple factors
- **Historical Analysis**: Track and analyze security events over time
- **Database-backed Reports**: PostgreSQL storage with JSONB support

## 📸 Screenshots

| Feature | Screenshot |
|---------|------------|
| **Login Page** | ![Login Page](screenshots/login_page.png) |
| **Dashboard** | ![Dashboard](screenshots/dashboard.png) |
| **Reports View** | ![Reports](screenshots/reports.png) |

## 📋 Prerequisites

- **Python 3.9** or higher
- **PostgreSQL** database
- **API Keys** for:
  - [AbuseIPDB](https://www.abuseipdb.com/account/api) - IP reputation data
  - [VirusTotal](https://www.virustotal.com/join-us) - Malware intelligence
  - [Shodan](https://account.shodan.io/register) - Network intelligence
  - [HttpBL](https://www.projecthoneypot.org/httpbl.php) - DNS blacklist (optional)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/threat_intel_aggregator.git
cd threat_intel_aggregator
```

### 2. Set Up Virtual Environment
```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the project root:
```env
# API Keys
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
SHODAN_API_KEY=your_shodan_key_here
HTTPBL_ACCESS_KEY=your_httpbl_key_here

# Flask Configuration
FLASK_SECRET_KEY=your_secret_key_here
FLASK_ENV=development

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost/threat_intel_db
```

### 5. Set Up Database
```bash
# Create PostgreSQL database
createdb threat_intel_db

# Run database migrations
python add_reports_table.py
```

## 🚀 Quick Start

### Start the Web Server
```bash
python run.py
```

### Access the Dashboard
1. Open your browser and navigate to `http://localhost:5000`
2. **For new users**: Click "Register" to create an account
3. **For existing users**: Log in with your credentials
4. **Default admin account**:
   - **Username**: `admin`
   - **Password**: `admin123`

### User Management

#### Self-Registration
New users can create accounts through the web interface:
1. Click "Register" in the navigation bar
2. Fill out the registration form with:
   - Username (3-20 characters, alphanumeric with underscore/dash)
   - Email address
   - Strong password (8+ chars, uppercase, lowercase, number, special char)
   - Password confirmation
   - Terms of service agreement
3. Click "Create Account"
4. Log in with your new credentials

#### Administrative User Management
Use the command-line tool for user administration:

```bash
# List all users
python manage_users.py list

# Create a new user
python manage_users.py create username email@example.com Password123!

# Delete a user
python manage_users.py delete username

# Reset user password
python manage_users.py reset-password username NewPassword123!

# Show user details
python manage_users.py show username
```

#### Security Features
- **Password Requirements**: Minimum 8 characters with uppercase, lowercase, number, and special character
- **Username Validation**: 3-20 characters, alphanumeric with underscore/dash
- **Email Validation**: Proper email format required
- **Duplicate Prevention**: Username and email must be unique
- **Terms Agreement**: Users must agree to Terms of Service and Privacy Policy
- **Admin Protection**: Default admin account cannot be deleted

### Test the Integration
```bash
python test_integration.py
```

## 📁 Project Structure

```
threat_intel_aggregator/
├── 📂 api_clients/              # Threat intelligence API clients
│   ├── abuseipdb_client.py
│   ├── virustotal_client.py
│   ├── shodan_client.py
│   └── base.py
├── 📂 network_monitoring/       # Network monitoring components
│   ├── connection_monitor.py
│   ├── process_monitor.py
│   ├── threat_detector.py
│   ├── yara_scanner.py
│   └── 📂 yara_rules/          # YARA malware detection rules
├── 📂 integration/              # Integration layer
│   ├── event_correlator.py
│   ├── unified_alerter.py
│   └── network_monitor_manager.py
├── 📂 web_dashboard/            # Web application
│   ├── 📂 templates/           # HTML templates
│   ├── 📂 static/             # Static files (CSS, JS)
│   ├── models.py              # Database models
│   └── routes.py              # Route handlers
├── 📂 threat_intelligence/      # MITRE ATT&CK integration
├── 📂 reports/                 # Generated reports
├── 📂 cache/                   # Cached threat intelligence data
├── run.py                     # Web server entry point
├── requirements.txt           # Project dependencies
└── README.md                 # This file
```

## 🔌 API Integration

The application integrates with four major threat intelligence APIs:

| API | Purpose | Features |
|-----|---------|----------|
| **AbuseIPDB** | IP Reputation | IP reputation checking, abuse confidence scoring, country/ISP info |
| **VirusTotal** | Malware Detection | Malware detection, network activity analysis, community reputation |
| **Shodan** | Network Intelligence | Port scanning, service detection, vulnerability assessment |
| **HttpBL** | DNS Blacklist | DNS-based blacklist checking, threat scoring, visitor classification |

## 🔧 Configuration

### Alert Thresholds
Configure alert sensitivity in the integration components:
- Network connection threat score threshold
- Process risk level thresholds
- YARA match thresholds
- Correlation score thresholds

### Monitoring Settings
- Connection monitoring interval
- Process monitoring frequency
- YARA scan frequency
- Cache TTL settings

## 🛡️ Security Features

### Real-time Monitoring
- **Connection Tracking**: Monitor all TCP/UDP connections
- **Process Analysis**: Track processes and their network activity
- **YARA Scanning**: Local malware detection using YARA rules
- **Behavioral Analysis**: Detect suspicious process behavior

### Threat Correlation
- **Automatic Enrichment**: Correlate local events with external threat intelligence
- **Risk Scoring**: Calculate comprehensive threat scores
- **Alert Generation**: Generate alerts based on correlation results
- **Cache Management**: Efficient caching of threat intelligence results

### Data Privacy
- **Local Processing**: Network monitoring runs locally
- **Secure Storage**: Encrypted storage of sensitive data
- **API Rate Limiting**: Respect API rate limits
- **Cache Management**: Automatic cache expiration

## 🐛 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Import Errors** | Ensure all dependencies are installed: `pip install -r requirements.txt` |
| **API Errors** | Verify API keys are correct and have sufficient quota |
| **Permission Errors** | Network monitoring may require elevated privileges |
| **Database Errors** | Check PostgreSQL connection and run migrations |

### Debug Mode
Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- [VirusTotal](https://www.virustotal.com/) for malware intelligence
- [Shodan](https://www.shodan.io/) for network intelligence
- [HttpBL](https://www.projecthoneypot.org/httpbl.php) for DNS blacklist data
- [YARA](https://github.com/VirusTotal/yara) for malware detection rules
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [MITRE ATT&CK](https://attack.mitre.org/) for threat intelligence framework

## 📞 Support

If you encounter any issues or have questions:
- Open an [Issue](https://github.com/yourusername/threat_intel_aggregator/issues)
- Check the [Wiki](https://github.com/yourusername/threat_intel_aggregator/wiki) for detailed documentation

---

**⭐ Star this repository if you find it useful!**
