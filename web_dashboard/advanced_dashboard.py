"""
Advanced Dashboard

This module provides enhanced dashboard functionality with advanced
visualizations, threat intelligence integration, and real-time analytics.
"""

import plotly.graph_objs as go
import plotly.express as px
from plotly.subplots import make_subplots
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class AdvancedDashboard:
    """Advanced dashboard with enhanced visualizations and threat intelligence."""
    
    def __init__(self):
        """Initialize the advanced dashboard."""
        self.color_scheme = {
            'primary': '#1f77b4',
            'secondary': '#ff7f0e', 
            'success': '#2ca02c',
            'danger': '#d62728',
            'warning': '#ff7f0e',
            'info': '#17a2b8',
            'light': '#f8f9fa',
            'dark': '#343a40'
        }
    
    def create_threat_intelligence_dashboard(self, threat_data: Dict) -> Dict:
        """Create comprehensive threat intelligence dashboard."""
        try:
            dashboard = {
                'layout': self._create_dashboard_layout(),
                'charts': {}
            }
            
            # Threat Score Overview
            dashboard['charts']['threat_score'] = self._create_threat_score_chart(threat_data)
            
            # Threat Categories Distribution
            dashboard['charts']['threat_categories'] = self._create_threat_categories_chart(threat_data)
            
            # Timeline of Threats
            dashboard['charts']['threat_timeline'] = self._create_threat_timeline_chart(threat_data)
            
            # Geographic Threat Distribution
            dashboard['charts']['geo_threats'] = self._create_geo_threat_chart(threat_data)
            
            # MITRE ATT&CK Matrix
            dashboard['charts']['attack_matrix'] = self._create_attack_matrix_chart(threat_data)
            
            # Threat Actor Activity
            dashboard['charts']['threat_actors'] = self._create_threat_actors_chart(threat_data)
            
            # Malware Family Distribution
            dashboard['charts']['malware_families'] = self._create_malware_families_chart(threat_data)
            
            # Network Traffic Analysis
            dashboard['charts']['network_traffic'] = self._create_network_traffic_chart(threat_data)
            
            # Process Monitoring
            dashboard['charts']['process_monitoring'] = self._create_process_monitoring_chart(threat_data)
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Error creating threat intelligence dashboard: {e}")
            return {'error': str(e)}
    
    def _create_dashboard_layout(self) -> Dict:
        """Create the main dashboard layout."""
        return {
            'title': 'Advanced Threat Intelligence Dashboard',
            'template': 'plotly_white',
            'height': 1200,
            'showlegend': True,
            'margin': {'l': 50, 'r': 50, 't': 50, 'b': 50}
        }
    
    def _create_threat_score_chart(self, threat_data: Dict) -> Dict:
        """Create threat score gauge chart."""
        try:
            # Calculate overall threat score
            threat_score = threat_data.get('overall_threat_score', 0)
            
            # Determine color based on score
            if threat_score >= 80:
                color = self.color_scheme['danger']
            elif threat_score >= 60:
                color = self.color_scheme['warning']
            elif threat_score >= 40:
                color = self.color_scheme['info']
            else:
                color = self.color_scheme['success']
            
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=threat_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Overall Threat Score"},
                delta={'reference': 50},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': color},
                    'steps': [
                        {'range': [0, 25], 'color': self.color_scheme['success']},
                        {'range': [25, 50], 'color': self.color_scheme['info']},
                        {'range': [50, 75], 'color': self.color_scheme['warning']},
                        {'range': [75, 100], 'color': self.color_scheme['danger']}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            
            fig.update_layout(
                title="Threat Score Overview",
                height=300,
                margin={'l': 20, 'r': 20, 't': 40, 'b': 20}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating threat score chart: {e}")
            return {}
    
    def _create_threat_categories_chart(self, threat_data: Dict) -> Dict:
        """Create threat categories pie chart."""
        try:
            categories = threat_data.get('threat_categories', {})
            
            if not categories:
                # Sample data
                categories = {
                    'Malware': 35,
                    'Phishing': 25,
                    'DDoS': 15,
                    'Data Breach': 10,
                    'APT': 10,
                    'Other': 5
                }
            
            fig = go.Figure(data=[go.Pie(
                labels=list(categories.keys()),
                values=list(categories.values()),
                hole=0.3,
                marker_colors=[self.color_scheme['primary'], self.color_scheme['secondary'],
                              self.color_scheme['success'], self.color_scheme['danger'],
                              self.color_scheme['warning'], self.color_scheme['info']]
            )])
            
            fig.update_layout(
                title="Threat Categories Distribution",
                height=400,
                margin={'l': 20, 'r': 20, 't': 40, 'b': 20}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating threat categories chart: {e}")
            return {}
    
    def _create_threat_timeline_chart(self, threat_data: Dict) -> Dict:
        """Create threat timeline chart."""
        try:
            timeline_data = threat_data.get('threat_timeline', [])
            
            if not timeline_data:
                # Generate sample timeline data without pandas/numpy
                from datetime import datetime, timedelta
                import random
                
                dates = []
                threats = []
                for i in range(30):
                    date = datetime.now() - timedelta(days=29-i)
                    dates.append(date.strftime('%Y-%m-%d'))
                    threats.append(random.randint(0, 20))
            else:
                dates = [item['date'] for item in timeline_data]
                threats = [item['threats'] for item in timeline_data]
            
            fig = go.Figure()
            
            # Add line for threat count
            fig.add_trace(go.Scatter(
                x=dates,
                y=threats,
                mode='lines+markers',
                name='Threat Count',
                line=dict(color=self.color_scheme['primary'], width=3),
                marker=dict(size=8)
            ))
            
            fig.update_layout(
                title="Threat Timeline (Last 30 Days)",
                xaxis_title="Date",
                yaxis_title="Number of Threats",
                height=400,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 50}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating threat timeline chart: {e}")
            return {}
    
    def _create_geo_threat_chart(self, threat_data: Dict) -> Dict:
        """Create geographic threat distribution chart."""
        try:
            geo_data = threat_data.get('geo_threats', {})
            
            if not geo_data:
                # Sample data
                geo_data = {
                    'United States': 45,
                    'China': 25,
                    'Russia': 15,
                    'North Korea': 8,
                    'Iran': 7
                }
            
            fig = go.Figure(data=go.Choropleth(
                locations=list(geo_data.keys()),
                z=list(geo_data.values()),
                locationmode='country names',
                colorscale='Reds',
                marker_line_color='darkgray',
                marker_line_width=0.5,
                colorbar_title="Threat Level"
            ))
            
            fig.update_layout(
                title="Geographic Threat Distribution",
                geo=dict(
                    showframe=False,
                    showcoastlines=True,
                    projection_type='equirectangular'
                ),
                height=400,
                margin={'l': 20, 'r': 20, 't': 40, 'b': 20}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating geo threat chart: {e}")
            return {}
    
    def _create_attack_matrix_chart(self, threat_data: Dict) -> Dict:
        """Create MITRE ATT&CK matrix visualization."""
        try:
            # MITRE ATT&CK tactics
            tactics = [
                'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                'Collection', 'Command and Control', 'Exfiltration', 'Impact'
            ]
            
            # Sample technique data
            techniques_data = threat_data.get('attack_techniques', {})
            
            if not techniques_data:
                # Generate sample data
                techniques_data = {
                    'Initial Access': 5,
                    'Execution': 8,
                    'Persistence': 3,
                    'Privilege Escalation': 4,
                    'Defense Evasion': 6,
                    'Credential Access': 2,
                    'Discovery': 7,
                    'Lateral Movement': 3,
                    'Collection': 4,
                    'Command and Control': 5,
                    'Exfiltration': 2,
                    'Impact': 3
                }
            
            fig = go.Figure(data=go.Heatmap(
                z=[[techniques_data.get(tactic, 0) for tactic in tactics]],
                x=tactics,
                y=['Techniques'],
                colorscale='Reds',
                showscale=True,
                colorbar_title="Number of Techniques"
            ))
            
            fig.update_layout(
                title="MITRE ATT&CK Matrix Overview",
                xaxis_title="Tactics",
                yaxis_title="",
                height=300,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 100},
                xaxis={'tickangle': 45}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating attack matrix chart: {e}")
            return {}
    
    def _create_threat_actors_chart(self, threat_data: Dict) -> Dict:
        """Create threat actors activity chart."""
        try:
            actors_data = threat_data.get('threat_actors', {})
            
            if not actors_data:
                # Sample data
                actors_data = {
                    'APT29': 15,
                    'APT28': 12,
                    'Lazarus Group': 10,
                    'Wizard Spider': 8,
                    'Cobalt Group': 6,
                    'DarkHydrus': 5
                }
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(actors_data.keys()),
                    y=list(actors_data.values()),
                    marker_color=self.color_scheme['danger']
                )
            ])
            
            fig.update_layout(
                title="Threat Actor Activity",
                xaxis_title="Threat Actors",
                yaxis_title="Activity Level",
                height=400,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 100},
                xaxis={'tickangle': 45}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating threat actors chart: {e}")
            return {}
    
    def _create_malware_families_chart(self, threat_data: Dict) -> Dict:
        """Create malware families distribution chart."""
        try:
            malware_data = threat_data.get('malware_families', {})
            
            if not malware_data:
                # Sample data
                malware_data = {
                    'Emotet': 25,
                    'TrickBot': 20,
                    'Ryuk': 15,
                    'Conti': 12,
                    'QakBot': 10,
                    'Revil': 8,
                    'Other': 10
                }
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(malware_data.keys()),
                    y=list(malware_data.values()),
                    marker_color=self.color_scheme['warning']
                )
            ])
            
            fig.update_layout(
                title="Malware Families Distribution",
                xaxis_title="Malware Families",
                yaxis_title="Detection Count",
                height=400,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 100},
                xaxis={'tickangle': 45}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating malware families chart: {e}")
            return {}
    
    def _create_network_traffic_chart(self, threat_data: Dict) -> Dict:
        """Create network traffic analysis chart."""
        try:
            traffic_data = threat_data.get('network_traffic', {})
            
            if not traffic_data:
                # Sample data
                traffic_data = {
                    'HTTP': 40,
                    'HTTPS': 35,
                    'DNS': 15,
                    'SSH': 5,
                    'FTP': 3,
                    'Other': 2
                }
            
            fig = go.Figure(data=[go.Pie(
                labels=list(traffic_data.keys()),
                values=list(traffic_data.values()),
                hole=0.4,
                marker_colors=px.colors.qualitative.Set3
            )])
            
            fig.update_layout(
                title="Network Traffic Analysis",
                height=400,
                margin={'l': 20, 'r': 20, 't': 40, 'b': 20}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating network traffic chart: {e}")
            return {}
    
    def _create_process_monitoring_chart(self, threat_data: Dict) -> Dict:
        """Create process monitoring chart."""
        try:
            process_data = threat_data.get('process_monitoring', {})
            
            if not process_data:
                # Sample data
                process_data = {
                    'System': 30,
                    'Chrome': 15,
                    'Explorer': 10,
                    'svchost': 8,
                    'Python': 5,
                    'Other': 32
                }
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(process_data.keys()),
                    y=list(process_data.values()),
                    marker_color=self.color_scheme['info']
                )
            ])
            
            fig.update_layout(
                title="Process Monitoring",
                xaxis_title="Processes",
                yaxis_title="CPU Usage (%)",
                height=400,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 100},
                xaxis={'tickangle': 45}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating process monitoring chart: {e}")
            return {}
    
    def create_security_news_dashboard(self, news_data: List[Dict]) -> Dict:
        """Create security news dashboard."""
        try:
            dashboard = {
                'layout': self._create_dashboard_layout(),
                'charts': {}
            }
            
            # News timeline
            dashboard['charts']['news_timeline'] = self._create_news_timeline_chart(news_data)
            
            # Threat categories from news
            dashboard['charts']['news_categories'] = self._create_news_categories_chart(news_data)
            
            # Source distribution
            dashboard['charts']['news_sources'] = self._create_news_sources_chart(news_data)
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Error creating security news dashboard: {e}")
            return {'error': str(e)}
    
    def _create_news_timeline_chart(self, news_data: List[Dict]) -> Dict:
        """Create news timeline chart."""
        try:
            if not news_data:
                return {}
            
            # Group news by date
            news_by_date = {}
            for article in news_data:
                date = article.get('published_date', '').split('T')[0]
                if date not in news_by_date:
                    news_by_date[date] = []
                news_by_date[date].append(article)
            
            dates = sorted(news_by_date.keys())
            counts = [len(news_by_date[date]) for date in dates]
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                name='Articles Published',
                line=dict(color=self.color_scheme['primary'], width=3),
                marker=dict(size=8)
            ))
            
            fig.update_layout(
                title="Security News Timeline",
                xaxis_title="Date",
                yaxis_title="Number of Articles",
                height=400,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 50}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating news timeline chart: {e}")
            return {}
    
    def _create_news_categories_chart(self, news_data: List[Dict]) -> Dict:
        """Create news categories chart."""
        try:
            if not news_data:
                return {}
            
            # Count categories
            categories = {}
            for article in news_data:
                article_categories = article.get('threat_intelligence', {}).get('categories', [])
                for category in article_categories:
                    categories[category] = categories.get(category, 0) + 1
            
            if not categories:
                return {}
            
            fig = go.Figure(data=[go.Pie(
                labels=list(categories.keys()),
                values=list(categories.values()),
                hole=0.3,
                marker_colors=px.colors.qualitative.Set3
            )])
            
            fig.update_layout(
                title="News Categories Distribution",
                height=400,
                margin={'l': 20, 'r': 20, 't': 40, 'b': 20}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating news categories chart: {e}")
            return {}
    
    def _create_news_sources_chart(self, news_data: List[Dict]) -> Dict:
        """Create news sources chart."""
        try:
            if not news_data:
                return {}
            
            # Count sources
            sources = {}
            for article in news_data:
                source = article.get('source', 'Unknown')
                sources[source] = sources.get(source, 0) + 1
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(sources.keys()),
                    y=list(sources.values()),
                    marker_color=self.color_scheme['secondary']
                )
            ])
            
            fig.update_layout(
                title="News Sources Distribution",
                xaxis_title="Sources",
                yaxis_title="Number of Articles",
                height=400,
                margin={'l': 50, 'r': 20, 't': 40, 'b': 100},
                xaxis={'tickangle': 45}
            )
            
            return fig.to_dict()
            
        except Exception as e:
            logger.error(f"Error creating news sources chart: {e}")
            return {}

# Global instance
advanced_dashboard = AdvancedDashboard() 