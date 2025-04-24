from app.services.nginx_service import NginxService
from app.services.caddy_service import CaddyService
from app.services.traefik_service import TraefikService

class ProxyServiceFactory:
    """
    Factory class for creating proxy service instances based on node type
    """
    
    @staticmethod
    def create_service(proxy_type):
        """
        Create a proxy service instance based on the proxy type
        
        Args:
            proxy_type: String identifier for the proxy service type (nginx, caddy, traefik)
            
        Returns:
            ProxyServiceBase: An instance of a concrete proxy service
            
        Raises:
            ValueError: If an unsupported proxy type is provided
        """
        proxy_type = proxy_type.lower() if proxy_type else 'nginx'
        
        if proxy_type == 'nginx':
            return NginxService()
        elif proxy_type == 'caddy':
            return CaddyService()
        elif proxy_type == 'traefik':
            return TraefikService()
        else:
            raise ValueError(f"Unsupported proxy type: {proxy_type}")
    
    @staticmethod
    def get_supported_proxy_types():
        """
        Get a list of supported proxy types
        
        Returns:
            list: A list of supported proxy types
        """
        return ['nginx', 'caddy', 'traefik']