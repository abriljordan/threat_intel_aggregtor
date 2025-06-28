"""
Database Optimization and Management

This module provides database optimization, indexing, and management
for the threat intelligence aggregator.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy import create_engine, text, Index, func
from sqlalchemy.orm import sessionmaker
from web_dashboard import db
from web_dashboard.models import Report, User

logger = logging.getLogger(__name__)

class DatabaseOptimizer:
    """Database optimization and management utilities."""
    
    def __init__(self, app=None):
        """Initialize database optimizer."""
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app."""
        self.app = app
        self.engine = db.engine
    
    def create_indexes(self):
        """Create database indexes for better performance."""
        try:
            with self.engine.connect() as conn:
                # Create indexes for Reports table
                indexes = [
                    # Composite index for target and timestamp
                    Index('idx_reports_target_timestamp', Report.target, Report.timestamp),
                    
                    # Index for abuse score queries
                    Index('idx_reports_abuse_score', Report.abuse_score),
                    
                    # Index for malicious reports
                    Index('idx_reports_is_malicious', Report.is_malicious),
                    
                    # Index for date range queries
                    Index('idx_reports_created_at', Report.created_at),
                    
                    # Composite index for threat analysis
                    Index('idx_reports_threat_analysis', Report.abuse_score, Report.is_malicious, Report.created_at),
                ]
                
                # Create indexes
                for index in indexes:
                    try:
                        index.create(self.engine)
                        logger.info(f"Created index: {index.name}")
                    except Exception as e:
                        logger.warning(f"Index {index.name} may already exist: {e}")
                
                logger.info("Database indexes created successfully")
                
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
    
    def analyze_table_performance(self):
        """Analyze table performance and provide recommendations."""
        try:
            with self.engine.connect() as conn:
                # Get table statistics
                result = conn.execute(text("""
                    SELECT 
                        schemaname,
                        tablename,
                        attname,
                        n_distinct,
                        correlation
                    FROM pg_stats 
                    WHERE schemaname = 'public'
                    ORDER BY tablename, attname
                """))
                
                stats = result.fetchall()
                
                # Analyze Reports table
                reports_stats = [row for row in stats if row[1] == 'reports']
                
                recommendations = []
                
                for stat in reports_stats:
                    if stat[2] == 'target' and stat[3] < 100:
                        recommendations.append("Consider adding more granular indexing on 'target' column")
                    
                    if stat[2] == 'abuse_score' and stat[4] < 0.1:
                        recommendations.append("Consider partitioning Reports table by abuse_score ranges")
                
                return {
                    'table_stats': stats,
                    'recommendations': recommendations
                }
                
        except Exception as e:
            logger.error(f"Error analyzing table performance: {e}")
            return {'error': str(e)}
    
    def partition_reports_table(self):
        """Partition Reports table by date for better performance."""
        try:
            with self.engine.connect() as conn:
                # Create partitioned table structure
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS reports_partitioned (
                        LIKE reports INCLUDING ALL
                    ) PARTITION BY RANGE (created_at)
                """))
                
                # Create monthly partitions for the last 12 months
                for i in range(12):
                    start_date = datetime.now() - timedelta(days=30*i)
                    end_date = start_date + timedelta(days=30)
                    
                    partition_name = f"reports_{start_date.strftime('%Y_%m')}"
                    
                    conn.execute(text(f"""
                        CREATE TABLE IF NOT EXISTS {partition_name} 
                        PARTITION OF reports_partitioned
                        FOR VALUES FROM ('{start_date.date()}') TO ('{end_date.date()}')
                    """))
                
                logger.info("Reports table partitioning created")
                
        except Exception as e:
            logger.error(f"Error partitioning reports table: {e}")
    
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old data to maintain performance."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            # Delete old reports
            old_reports = Report.query.filter(
                Report.created_at < cutoff_date
            ).delete()
            
            # Delete old cache files
            from cache_config import cache_config
            cache_config.cleanup_expired_cache()
            
            logger.info(f"Cleaned up {old_reports} old reports and expired cache files")
            
            return {
                'deleted_reports': old_reports,
                'cutoff_date': cutoff_date.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
            return {'error': str(e)}
    
    def get_database_stats(self) -> Dict:
        """Get comprehensive database statistics."""
        try:
            with self.engine.connect() as conn:
                # Get table sizes
                size_result = conn.execute(text("""
                    SELECT 
                        schemaname,
                        tablename,
                        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                        pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                    FROM pg_tables 
                    WHERE schemaname = 'public'
                    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                """))
                
                # Get row counts
                count_result = conn.execute(text("""
                    SELECT 
                        'reports' as table_name,
                        COUNT(*) as row_count
                    FROM reports
                    UNION ALL
                    SELECT 
                        'users' as table_name,
                        COUNT(*) as row_count
                    FROM users
                """))
                
                # Get recent activity
                activity_result = conn.execute(text("""
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as reports_count
                    FROM reports 
                    WHERE created_at >= NOW() - INTERVAL '30 days'
                    GROUP BY DATE(created_at)
                    ORDER BY date DESC
                """))
                
                return {
                    'table_sizes': [dict(row) for row in size_result],
                    'row_counts': [dict(row) for row in count_result],
                    'recent_activity': [dict(row) for row in activity_result],
                    'total_size_bytes': sum(row[3] for row in size_result),
                    'total_reports': sum(row[1] for row in count_result if row[0] == 'reports')
                }
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {'error': str(e)}
    
    def optimize_queries(self):
        """Optimize common queries with materialized views."""
        try:
            with self.engine.connect() as conn:
                # Create materialized view for threat statistics
                conn.execute(text("""
                    CREATE MATERIALIZED VIEW IF NOT EXISTS threat_stats AS
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as total_reports,
                        COUNT(CASE WHEN is_malicious THEN 1 END) as malicious_reports,
                        AVG(abuse_score) as avg_abuse_score,
                        MAX(abuse_score) as max_abuse_score
                    FROM reports
                    GROUP BY DATE(created_at)
                    ORDER BY date DESC
                """))
                
                # Create materialized view for top threats
                conn.execute(text("""
                    CREATE MATERIALIZED VIEW IF NOT EXISTS top_threats AS
                    SELECT 
                        target,
                        COUNT(*) as report_count,
                        AVG(abuse_score) as avg_score,
                        MAX(abuse_score) as max_score,
                        MAX(created_at) as last_seen
                    FROM reports
                    WHERE abuse_score > 50
                    GROUP BY target
                    ORDER BY avg_score DESC, report_count DESC
                    LIMIT 100
                """))
                
                logger.info("Materialized views created for query optimization")
                
        except Exception as e:
            logger.error(f"Error optimizing queries: {e}")
    
    def refresh_materialized_views(self):
        """Refresh materialized views with latest data."""
        try:
            with self.engine.connect() as conn:
                views = ['threat_stats', 'top_threats']
                
                for view in views:
                    conn.execute(text(f"REFRESH MATERIALIZED VIEW {view}"))
                    logger.info(f"Refreshed materialized view: {view}")
                
        except Exception as e:
            logger.error(f"Error refreshing materialized views: {e}")
    
    def backup_database(self, backup_path: str = None):
        """Create database backup."""
        try:
            if not backup_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"backups/threat_intel_backup_{timestamp}.sql"
            
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # Get database URL from environment
            database_url = os.getenv('DATABASE_URL', 'postgresql://localhost/threat_intel_db')
            
            # Create backup using pg_dump
            import subprocess
            result = subprocess.run([
                'pg_dump',
                '--dbname=' + database_url,
                '--file=' + backup_path,
                '--verbose'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Database backup created: {backup_path}")
                return {'success': True, 'backup_path': backup_path}
            else:
                logger.error(f"Backup failed: {result.stderr}")
                return {'success': False, 'error': result.stderr}
                
        except Exception as e:
            logger.error(f"Error creating database backup: {e}")
            return {'success': False, 'error': str(e)}

# Global database optimizer instance
db_optimizer = DatabaseOptimizer()

def optimize_database():
    """Run all database optimizations."""
    logger.info("Starting database optimization...")
    
    # Create indexes
    db_optimizer.create_indexes()
    
    # Optimize queries
    db_optimizer.optimize_queries()
    
    # Analyze performance
    performance = db_optimizer.analyze_table_performance()
    
    # Get statistics
    stats = db_optimizer.get_database_stats()
    
    logger.info("Database optimization completed")
    
    return {
        'performance_analysis': performance,
        'database_stats': stats
    }

if __name__ == "__main__":
    # Run optimization when script is executed directly
    result = optimize_database()
    print("Database optimization result:", result) 