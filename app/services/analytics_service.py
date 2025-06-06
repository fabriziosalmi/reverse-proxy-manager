import datetime
from datetime import timedelta
from flask import current_app
from sqlalchemy import func, and_, extract
from app.models.models import Site, Node, User
from app.models.analytics import SiteAnalytics, RequestLog, ErrorLog
from app import db

class AnalyticsService:
    """Service for handling analytics operations"""
    
    @staticmethod
    def get_admin_analytics():
        """Get analytics data for the admin dashboard"""
        try:
            today = datetime.datetime.utcnow().date()
            yesterday = today - timedelta(days=1)
            last_week = today - timedelta(days=7)
            
            # Get total sites and active sites - use count() for efficiency
            total_sites = Site.query.count()
            active_sites = Site.query.filter_by(is_active=True).count()
            
            # Get total nodes and active nodes
            total_nodes = Node.query.count()
            active_nodes = Node.query.filter_by(is_active=True).count()
            
            # Get total users
            total_users = User.query.count()
            
            # Calculate total traffic today - use scalar() for memory efficiency
            total_traffic_today = db.session.query(
                func.sum(SiteAnalytics.bandwidth_bytes)
            ).filter(
                func.date(SiteAnalytics.date) == today
            ).scalar() or 0
            
            # Calculate total traffic yesterday
            total_traffic_yesterday = db.session.query(
                func.sum(SiteAnalytics.bandwidth_bytes)
            ).filter(
                func.date(SiteAnalytics.date) == yesterday
            ).scalar() or 0
            
            # Calculate traffic growth
            traffic_growth = 0
            if total_traffic_yesterday > 0:
                traffic_growth = ((total_traffic_today - total_traffic_yesterday) / total_traffic_yesterday) * 100
            
            # Get top 5 sites by traffic - use specific columns instead of whole objects
            top_sites_query = db.session.query(
                Site.id, Site.domain, func.sum(SiteAnalytics.bandwidth_bytes).label('total_bandwidth')
            ).join(
                SiteAnalytics
            ).filter(
                func.date(SiteAnalytics.date) >= last_week
            ).group_by(
                Site.id, Site.domain  # Include all columns in GROUP BY for strict SQL modes
            ).order_by(
                func.sum(SiteAnalytics.bandwidth_bytes).desc()
            ).limit(5)
            
            # Execute the query and get results
            top_sites_data = top_sites_query.all()
            
            # Format the results
            top_sites = []
            for site_id, domain, bandwidth in top_sites_data:
                site_info = {'id': site_id, 'domain': domain}
                top_sites.append((site_info, AnalyticsService.format_bytes(bandwidth)))
            
            # Get top 5 sites by requests - optimize the same way
            top_sites_by_requests_query = db.session.query(
                Site.id, Site.domain, func.sum(SiteAnalytics.requests).label('total_requests')
            ).join(
                SiteAnalytics
            ).filter(
                func.date(SiteAnalytics.date) >= last_week
            ).group_by(
                Site.id, Site.domain
            ).order_by(
                func.sum(SiteAnalytics.requests).desc()
            ).limit(5)
            
            top_sites_by_requests = []
            for site_id, domain, requests in top_sites_by_requests_query.all():
                site_info = {'id': site_id, 'domain': domain}
                top_sites_by_requests.append((site_info, requests))
            
            # Get recent errors - only fetch needed columns
            recent_errors = ErrorLog.query.with_entities(
                ErrorLog.id, ErrorLog.site_id, ErrorLog.path, ErrorLog.status_code, 
                ErrorLog.message, ErrorLog.timestamp
            ).order_by(ErrorLog.timestamp.desc()).limit(10).all()
            
            # Prepare data for the dashboard charts
            # Last 7 days traffic chart
            last_7_days = []
            traffic_7_days = []
            
            for i in range(6, -1, -1):
                day = today - timedelta(days=i)
                last_7_days.append(day.strftime('%d %b'))
                
                traffic = db.session.query(
                    func.sum(SiteAnalytics.bandwidth_bytes)
                ).filter(
                    func.date(SiteAnalytics.date) == day
                ).scalar() or 0
                
                # Convert bytes to MB for better readability
                traffic_7_days.append(round(traffic / (1024 * 1024), 2))
            
            # Format traffic numbers for display
            total_traffic_today_formatted = AnalyticsService.format_bytes(total_traffic_today)
            total_traffic_yesterday_formatted = AnalyticsService.format_bytes(total_traffic_yesterday)
            
            # Return all data for the dashboard
            return {
                'total_sites': total_sites,
                'active_sites': active_sites,
                'total_nodes': total_nodes,
                'active_nodes': active_nodes,
                'total_users': total_users,
                'total_traffic_today': total_traffic_today_formatted,
                'total_traffic_yesterday': total_traffic_yesterday_formatted,
                'traffic_growth': round(traffic_growth, 2),
                'top_sites': top_sites,
                'top_sites_by_requests': top_sites_by_requests,
                'recent_errors': recent_errors,
                'chart_labels': last_7_days,
                'chart_data': traffic_7_days
            }
        except Exception as e:
            # Log the error and return an empty data structure to prevent dashboard failure
            current_app.logger.error(f"Error generating admin analytics: {str(e)}")
            return {
                'total_sites': 0,
                'active_sites': 0,
                'total_nodes': 0,
                'active_nodes': 0,
                'total_users': 0,
                'total_traffic_today': '0 B',
                'total_traffic_yesterday': '0 B',
                'traffic_growth': 0,
                'top_sites': [],
                'top_sites_by_requests': [],
                'recent_errors': [],
                'chart_labels': [],
                'chart_data': [],
                'error': str(e)
            }
    
    @staticmethod
    def get_client_analytics(user_id, site_id=None):
        """Get analytics data for a client's dashboard"""
        try:
            today = datetime.datetime.utcnow().date()
            yesterday = today - timedelta(days=1)
            last_week = today - timedelta(days=7)
            
            # Get user's sites with only necessary fields
            if site_id:
                sites = Site.query.with_entities(Site.id, Site.domain, Site.protocol).filter(
                    Site.user_id == user_id,
                    Site.id == site_id
                ).all()
            else:
                sites = Site.query.with_entities(Site.id, Site.domain, Site.protocol).filter_by(
                    user_id=user_id
                ).all()
            
            site_ids = [site.id for site in sites]
            
            if not site_ids:
                # No sites found
                return {
                    'sites': [],
                    'selected_site': None,
                    'total_traffic': '0 B',
                    'total_requests': 0,
                    'traffic_growth': 0,
                    'chart_labels': [],
                    'chart_data': []
                }
            
            # Get total traffic for all sites
            total_traffic = db.session.query(
                func.sum(SiteAnalytics.bandwidth_bytes)
            ).filter(
                SiteAnalytics.site_id.in_(site_ids),
                func.date(SiteAnalytics.date) >= last_week
            ).scalar() or 0
            
            # Get total traffic yesterday
            total_traffic_yesterday = db.session.query(
                func.sum(SiteAnalytics.bandwidth_bytes)
            ).filter(
                SiteAnalytics.site_id.in_(site_ids),
                func.date(SiteAnalytics.date) == yesterday
            ).scalar() or 0
            
            # Get total traffic today
            total_traffic_today = db.session.query(
                func.sum(SiteAnalytics.bandwidth_bytes)
            ).filter(
                SiteAnalytics.site_id.in_(site_ids),
                func.date(SiteAnalytics.date) == today
            ).scalar() or 0
            
            # Calculate traffic growth
            traffic_growth = 0
            if total_traffic_yesterday > 0:
                traffic_growth = ((total_traffic_today - total_traffic_yesterday) / total_traffic_yesterday) * 100
            
            # Get total requests
            total_requests = db.session.query(
                func.sum(SiteAnalytics.requests)
            ).filter(
                SiteAnalytics.site_id.in_(site_ids),
                func.date(SiteAnalytics.date) >= last_week
            ).scalar() or 0
            
            # Prepare data for the charts
            # Last 7 days traffic chart
            last_7_days = []
            traffic_7_days = []
            
            for i in range(6, -1, -1):
                day = today - timedelta(days=i)
                last_7_days.append(day.strftime('%d %b'))
                
                traffic = db.session.query(
                    func.sum(SiteAnalytics.bandwidth_bytes)
                ).filter(
                    SiteAnalytics.site_id.in_(site_ids),
                    func.date(SiteAnalytics.date) == day
                ).scalar() or 0
                
                # Convert bytes to MB for better readability
                traffic_7_days.append(round(traffic / (1024 * 1024), 2))
            
            # Get recent errors for these sites (only needed fields)
            recent_errors = ErrorLog.query.with_entities(
                ErrorLog.id, ErrorLog.site_id, ErrorLog.path, 
                ErrorLog.status_code, ErrorLog.message, ErrorLog.timestamp
            ).filter(
                ErrorLog.site_id.in_(site_ids)
            ).order_by(
                ErrorLog.timestamp.desc()
            ).limit(10).all()
            
            # Get selected site if site_id is provided
            selected_site = None
            if site_id:
                selected_site = Site.query.get(site_id)
            
            # Return all data for the dashboard
            return {
                'sites': sites,
                'selected_site': selected_site,
                'total_traffic': AnalyticsService.format_bytes(total_traffic),
                'total_requests': total_requests,
                'traffic_growth': round(traffic_growth, 2),
                'recent_errors': recent_errors,
                'chart_labels': last_7_days,
                'chart_data': traffic_7_days
            }
        except Exception as e:
            # Log the error and return an empty data structure
            current_app.logger.error(f"Error generating client analytics: {str(e)}")
            return {
                'sites': [],
                'selected_site': None,
                'total_traffic': '0 B',
                'total_requests': 0,
                'traffic_growth': 0,
                'recent_errors': [],
                'chart_labels': [],
                'chart_data': [],
                'error': str(e)
            }
    
    @staticmethod
    def get_api_analytics_data(period='week', site_id=None, real_time=False):
        """Get analytics data for API endpoints"""
        today = datetime.datetime.utcnow().date()
        
        if period == 'day':
            start_date = today
        elif period == 'week':
            start_date = today - timedelta(days=7)
        elif period == 'month':
            start_date = today - timedelta(days=30)
        elif period == 'year':
            start_date = today - timedelta(days=365)
        else:
            start_date = today - timedelta(days=7)  # Default to week
        
        # Base query
        query = db.session.query(
            func.date(SiteAnalytics.date).label('day'),
            func.sum(SiteAnalytics.requests).label('requests'),
            func.sum(SiteAnalytics.bandwidth_bytes).label('bandwidth'),
            func.sum(SiteAnalytics.cache_hits).label('cache_hits'),
            func.avg(SiteAnalytics.response_time_ms).label('avg_response_time')
        )
        
        # Apply site filter if provided
        if site_id:
            query = query.filter(SiteAnalytics.site_id == site_id)
        
        # Complete the query
        results = query.filter(
            func.date(SiteAnalytics.date) >= start_date
        ).group_by(
            func.date(SiteAnalytics.date)
        ).order_by(
            func.date(SiteAnalytics.date)
        ).all()
        
        # Prepare data for charts
        dates = []
        requests_data = []
        bandwidth_data = []
        cache_hit_rate = []
        response_times = []
        
        for result in results:
            dates.append(result.day.strftime('%d %b'))
            requests_data.append(result.requests)
            bandwidth_data.append(round(result.bandwidth / (1024 * 1024), 2))  # MB
            
            if result.requests > 0:
                hit_rate = (result.cache_hits / result.requests) * 100
            else:
                hit_rate = 0
            cache_hit_rate.append(round(hit_rate, 2))
            
            response_times.append(round(result.avg_response_time, 2))
        
        # For real-time data, we might add some simulated data points
        # In a real application, this would come from actual real-time monitoring
        if real_time:
            import random
            real_time_data = []
            
            # Generate data points for the last hour (60 minutes)
            now = datetime.datetime.utcnow()
            for i in range(60, 0, -1):
                minute_ago = now - timedelta(minutes=i)
                real_time_data.append({
                    'timestamp': minute_ago.strftime('%H:%M'),
                    'requests': random.randint(10, 100),
                    'response_time': random.uniform(50, 200)
                })
            
            return {
                'dates': dates,
                'requests': requests_data,
                'bandwidth': bandwidth_data,
                'cache_hit_rate': cache_hit_rate,
                'response_times': response_times,
                'real_time': real_time_data
            }
        
        return {
            'dates': dates,
            'requests': requests_data,
            'bandwidth': bandwidth_data,
            'cache_hit_rate': cache_hit_rate,
            'response_times': response_times
        }
    
    @staticmethod
    def record_request(site_id, path, status_code, response_time_ms, bytes_sent, is_cache_hit=False,
                      country_code=None, method='GET', user_agent=None, referer=None):
        """Record a request for analytics purposes"""
        try:
            # Add to individual request logs
            request_log = RequestLog(
                site_id=site_id,
                path=path,
                status_code=status_code,
                response_time_ms=response_time_ms,
                bytes_sent=bytes_sent,
                is_cache_hit=is_cache_hit,
                country_code=country_code,
                request_method=method,
                user_agent=user_agent,
                referer=referer
            )
            db.session.add(request_log)
            
            # Update or create daily analytics record
            today = datetime.datetime.utcnow().date()
            
            # Try to get existing analytics record for today
            analytics = SiteAnalytics.query.filter(
                SiteAnalytics.site_id == site_id,
                func.date(SiteAnalytics.date) == today
            ).first()
            
            if analytics:
                # Update existing record
                analytics.requests += 1
                analytics.bandwidth_bytes += bytes_sent
                
                if is_cache_hit:
                    analytics.cache_hits += 1
                
                # Update average response time
                analytics.response_time_ms = (
                    (analytics.response_time_ms * (analytics.requests - 1)) + response_time_ms
                ) / analytics.requests
            else:
                # Create new record
                analytics = SiteAnalytics(
                    site_id=site_id,
                    date=today,
                    requests=1,
                    bandwidth_bytes=bytes_sent,
                    cache_hits=1 if is_cache_hit else 0,
                    response_time_ms=response_time_ms
                )
                db.session.add(analytics)
            
            # If error status code, log it
            if status_code >= 400:
                error_log = ErrorLog(
                    site_id=site_id,
                    path=path,
                    status_code=status_code,
                    message=f"HTTP {status_code} error"
                )
                db.session.add(error_log)
            
            db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error(f"Error recording analytics: {str(e)}")
            db.session.rollback()
            return False
    
    @staticmethod
    def format_bytes(bytes_value):
        """Format bytes to human-readable form"""
        if bytes_value < 1024:
            return f"{bytes_value} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value/1024:.2f} KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value/(1024*1024):.2f} MB"
        else:
            return f"{bytes_value/(1024*1024*1024):.2f} GB"
    
    @staticmethod
    def get_site_performance_metrics(site_id, period='week'):
        """
        Get detailed performance metrics for a specific site
        
        Args:
            site_id: ID of the site to analyze
            period: 'day', 'week', 'month', or 'year'
            
        Returns:
            dict: Detailed performance metrics
        """
        try:
            today = datetime.datetime.utcnow().date()
            
            # Determine start date based on period
            if period == 'day':
                start_date = today
            elif period == 'week':
                start_date = today - timedelta(days=7)
            elif period == 'month':
                start_date = today - timedelta(days=30)
            elif period == 'year':
                start_date = today - timedelta(days=365)
            else:
                start_date = today - timedelta(days=7)  # Default to week
            
            # Verify site exists
            site = Site.query.get(site_id)
            if not site:
                return {'error': 'Site not found'}
            
            # Get basic analytics data
            analytics_data = db.session.query(
                func.sum(SiteAnalytics.requests).label('total_requests'),
                func.sum(SiteAnalytics.bandwidth_bytes).label('total_bandwidth'),
                func.sum(SiteAnalytics.cache_hits).label('total_cache_hits'),
                func.avg(SiteAnalytics.response_time_ms).label('avg_response_time')
            ).filter(
                SiteAnalytics.site_id == site_id,
                func.date(SiteAnalytics.date) >= start_date
            ).first()
            
            # Calculate cache hit ratio
            total_requests = analytics_data.total_requests or 0
            total_cache_hits = analytics_data.total_cache_hits or 0
            cache_hit_ratio = 0
            if total_requests > 0:
                cache_hit_ratio = (total_cache_hits / total_requests) * 100
            
            # Get HTTP status code distribution
            status_code_distribution = db.session.query(
                RequestLog.status_code,
                func.count(RequestLog.id).label('count')
            ).filter(
                RequestLog.site_id == site_id,
                RequestLog.timestamp >= datetime.datetime.combine(start_date, datetime.time.min)
            ).group_by(
                RequestLog.status_code
            ).all()
            
            # Organize status codes by category
            status_codes = {
                '2xx': 0,  # Success
                '3xx': 0,  # Redirection
                '4xx': 0,  # Client Error
                '5xx': 0   # Server Error
            }
            
            for code, count in status_code_distribution:
                if 200 <= code < 300:
                    status_codes['2xx'] += count
                elif 300 <= code < 400:
                    status_codes['3xx'] += count
                elif 400 <= code < 500:
                    status_codes['4xx'] += count
                elif 500 <= code < 600:
                    status_codes['5xx'] += count
            
            # Get most common error paths
            common_errors = db.session.query(
                RequestLog.path,
                RequestLog.status_code,
                func.count(RequestLog.id).label('count')
            ).filter(
                RequestLog.site_id == site_id,
                RequestLog.status_code >= 400,
                RequestLog.timestamp >= datetime.datetime.combine(start_date, datetime.time.min)
            ).group_by(
                RequestLog.path,
                RequestLog.status_code
            ).order_by(
                func.count(RequestLog.id).desc()
            ).limit(5).all()
            
            # Get geographic distribution (if available)
            geo_distribution = db.session.query(
                RequestLog.country_code,
                func.count(RequestLog.id).label('count')
            ).filter(
                RequestLog.site_id == site_id,
                RequestLog.country_code.isnot(None),
                RequestLog.timestamp >= datetime.datetime.combine(start_date, datetime.time.min)
            ).group_by(
                RequestLog.country_code
            ).order_by(
                func.count(RequestLog.id).desc()
            ).limit(10).all()
            
            # Get hourly traffic pattern
            hourly_traffic = db.session.query(
                extract('hour', RequestLog.timestamp).label('hour'),
                func.count(RequestLog.id).label('requests')
            ).filter(
                RequestLog.site_id == site_id,
                RequestLog.timestamp >= datetime.datetime.combine(start_date, datetime.time.min)
            ).group_by(
                extract('hour', RequestLog.timestamp)
            ).order_by(
                extract('hour', RequestLog.timestamp)
            ).all()
            
            # Format hourly data
            hours = [0] * 24  # Initialize with zeros
            for hour_data in hourly_traffic:
                hours[int(hour_data.hour)] = hour_data.requests
            
            # Get response time percentiles
            # This is an approximation - for precise percentiles, a specialized time-series DB is better
            response_times = db.session.query(
                RequestLog.response_time_ms
            ).filter(
                RequestLog.site_id == site_id,
                RequestLog.timestamp >= datetime.datetime.combine(start_date, datetime.time.min)
            ).order_by(
                RequestLog.response_time_ms
            ).all()
            
            response_times = [r.response_time_ms for r in response_times]
            
            # Calculate percentiles
            percentiles = {}
            if response_times:
                response_times.sort()
                count = len(response_times)
                
                p50_index = int(count * 0.5)
                p90_index = int(count * 0.9)
                p95_index = int(count * 0.95)
                p99_index = int(count * 0.99)
                
                percentiles = {
                    'p50': response_times[p50_index] if p50_index < count else 0,
                    'p90': response_times[p90_index] if p90_index < count else 0,
                    'p95': response_times[p95_index] if p95_index < count else 0,
                    'p99': response_times[p99_index] if p99_index < count else 0,
                    'max': response_times[-1] if response_times else 0
                }
            
            # Compile and return all metrics
            return {
                'site': {
                    'id': site.id,
                    'domain': site.domain,
                    'protocol': site.protocol
                },
                'period': period,
                'total_requests': total_requests,
                'total_bandwidth': analytics_data.total_bandwidth or 0,
                'total_bandwidth_formatted': AnalyticsService.format_bytes(analytics_data.total_bandwidth or 0),
                'average_response_time': round(analytics_data.avg_response_time or 0, 2),
                'cache_hit_ratio': round(cache_hit_ratio, 2),
                'status_codes': status_codes,
                'common_errors': common_errors,
                'geo_distribution': geo_distribution,
                'hourly_traffic': hours,
                'response_time_percentiles': percentiles
            }
        except Exception as e:
            current_app.logger.error(f"Error getting site performance metrics: {str(e)}")
            return {
                'error': f"Error retrieving performance metrics: {str(e)}",
                'site_id': site_id,
                'period': period
            }