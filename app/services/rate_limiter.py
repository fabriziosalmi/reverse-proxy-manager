import time

class RateLimiter:
    """
    A memory-efficient rate limiter implementation with periodic cleanup
    to prevent memory leaks from storing client data indefinitely.
    
    This implementation uses a token bucket algorithm with a fixed window.
    """
    
    def __init__(self, limit=60, window=60, cleanup_interval=3600):
        """
        Initialize the rate limiter
        
        Args:
            limit: Maximum number of requests per window
            window: Time window in seconds
            cleanup_interval: How often to clean up expired entries (seconds)
        """
        self.limit = limit
        self.window = window
        self.cleanup_interval = cleanup_interval
        self.client_timestamps = {}
        self.last_cleanup = time.time()
    
    def is_allowed(self, client_id):
        """
        Check if a request from a client is allowed
        
        Args:
            client_id: Identifier for the client (IP address, API key, etc.)
            
        Returns:
            bool: Whether the request is allowed
        """
        current_time = time.time()
        
        # Check if we need to clean up old entries
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup(current_time)
        
        # Get or initialize timestamps for this client
        if client_id not in self.client_timestamps:
            self.client_timestamps[client_id] = []
            return True
        
        # Get timestamps for this client
        timestamps = self.client_timestamps[client_id]
        
        # Remove timestamps outside the current window
        window_start = current_time - self.window
        valid_timestamps = [ts for ts in timestamps if ts > window_start]
        
        # Update timestamps for this client
        self.client_timestamps[client_id] = valid_timestamps
        
        # Check if client has exceeded rate limit
        if len(valid_timestamps) < self.limit:
            # Add current timestamp and allow request
            self.client_timestamps[client_id].append(current_time)
            return True
        
        # Rate limit exceeded
        return False
    
    def get_remaining(self, client_id):
        """
        Get remaining requests for a client
        
        Args:
            client_id: Identifier for the client
            
        Returns:
            int: Number of requests remaining in the current window
        """
        current_time = time.time()
        
        # Get timestamps for this client
        if client_id not in self.client_timestamps:
            return self.limit
        
        # Get valid timestamps for this client
        window_start = current_time - self.window
        valid_timestamps = [ts for ts in self.client_timestamps[client_id] if ts > window_start]
        
        # Return remaining requests
        return max(0, self.limit - len(valid_timestamps))
    
    def get_reset_time(self, client_id):
        """
        Get time until rate limit reset for a client
        
        Args:
            client_id: Identifier for the client
            
        Returns:
            float: Time in seconds until the rate limit resets
        """
        current_time = time.time()
        
        # Get timestamps for this client
        if client_id not in self.client_timestamps:
            return 0
        
        # If no timestamps, return 0
        if not self.client_timestamps[client_id]:
            return 0
        
        # Get oldest timestamp in the current window
        window_start = current_time - self.window
        valid_timestamps = [ts for ts in self.client_timestamps[client_id] if ts > window_start]
        
        if not valid_timestamps:
            return 0
        
        # Return time until the oldest timestamp expires
        oldest_timestamp = min(valid_timestamps)
        return max(0, oldest_timestamp + self.window - current_time)
    
    def _cleanup(self, current_time=None):
        """
        Clean up expired entries to prevent memory leaks
        
        Args:
            current_time: Current time (defaults to time.time())
        """
        if current_time is None:
            current_time = time.time()
        
        # Set last cleanup time
        self.last_cleanup = current_time
        
        # Calculate cutoff time
        cutoff_time = current_time - self.window
        
        # Remove expired timestamps for all clients
        for client_id in list(self.client_timestamps.keys()):
            # Get valid timestamps for this client
            valid_timestamps = [ts for ts in self.client_timestamps[client_id] if ts > cutoff_time]
            
            if not valid_timestamps:
                # If no valid timestamps, remove the client entirely
                del self.client_timestamps[client_id]
            else:
                # Otherwise, update with valid timestamps
                self.client_timestamps[client_id] = valid_timestamps
    
    def reset(self, client_id=None):
        """
        Reset rate limit for a client or all clients
        
        Args:
            client_id: Identifier for the client (None to reset all)
        """
        if client_id is None:
            # Reset all clients
            self.client_timestamps = {}
        elif client_id in self.client_timestamps:
            # Reset specific client
            del self.client_timestamps[client_id]
    
    def set_limits(self, limit=None, window=None):
        """
        Update rate limits
        
        Args:
            limit: New request limit (or None to keep current)
            window: New time window in seconds (or None to keep current)
        """
        if limit is not None:
            self.limit = limit
        
        if window is not None:
            self.window = window
            
        # Clean up with new limits
        self._cleanup()


# Create global rate limiters for different API endpoints
api_rate_limiter = RateLimiter(limit=60, window=60)  # 60 requests per minute for general API
auth_rate_limiter = RateLimiter(limit=10, window=60)  # 10 login attempts per minute
ssl_cert_rate_limiter = RateLimiter(limit=5, window=300)  # 5 certificate requests per 5 minutes


def rate_limit_request(limiter, client_id):
    """
    Rate limit a request and set appropriate headers
    
    Args:
        limiter: RateLimiter instance to use
        client_id: Client identifier (usually IP address)
        
    Returns:
        tuple: (is_allowed, headers_dict)
    """
    # Check if request is allowed
    is_allowed = limiter.is_allowed(client_id)
    
    # Prepare rate limit headers
    headers = {
        'X-RateLimit-Limit': str(limiter.limit),
        'X-RateLimit-Remaining': str(limiter.get_remaining(client_id)),
        'X-RateLimit-Reset': str(int(limiter.get_reset_time(client_id)))
    }
    
    return is_allowed, headers