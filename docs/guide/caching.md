# Caching Configuration

Fine-grained control over content caching with multiple configuration options.

## Cache Settings

- **Enable/Disable Caching**: Toggle caching for each site
- **Content Cache Duration**: Set caching time for dynamic content (default: 3600 seconds / 1 hour)
- **Static Assets Cache Duration**: Configure longer cache times for static files like images, CSS, JS (default: 86400 seconds / 1 day)
- **Browser Cache Duration**: Set client-side cache-control headers (default: 3600 seconds)
- **Custom Cache Rules**: Add advanced Nginx cache directives for specialized requirements

## Implementation

- Utilizes Nginx's `proxy_cache` system with optimized settings
- Implements cache bypass for certain request types
- Configures stale cache usage during backend errors or updates
