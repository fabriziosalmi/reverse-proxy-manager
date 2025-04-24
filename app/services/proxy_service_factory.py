from app.services.nginx_service import NginxService
from app.services.caddy_service import CaddyService
from app.services.traefik_service import TraefikService
from app.services.proxy_service_base import ProxyServiceBase
from app.models.models import Node

class ProxyServiceFactory:
    """
    Factory class for creating proxy service instances based on node type
    """
    
    # Service class registry for dependency injection
    _service_registry = {
        'nginx': NginxService,
        'caddy': CaddyService,
        'traefik': TraefikService
    }
    
    # Singleton instances for better performance
    _service_instances = {}
    
    @classmethod
    def register_service(cls, proxy_type, service_class):
        """
        Register a new proxy service class
        
        Args:
            proxy_type: String identifier for the proxy service type
            service_class: Class that implements ProxyServiceBase
            
        Returns:
            bool: True if registered successfully, False if proxy_type already exists
        """
        if not issubclass(service_class, ProxyServiceBase):
            raise TypeError(f"Service class must inherit from ProxyServiceBase")
            
        if proxy_type in cls._service_registry:
            return False
            
        cls._service_registry[proxy_type] = service_class
        return True
    
    @classmethod
    def create_service(cls, proxy_type):
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
        
        # Check if we already have an instance
        if proxy_type in cls._service_instances:
            return cls._service_instances[proxy_type]
        
        # Create a new instance if needed
        if proxy_type in cls._service_registry:
            service = cls._service_registry[proxy_type]()
            cls._service_instances[proxy_type] = service
            return service
        else:
            raise ValueError(f"Unsupported proxy type: {proxy_type}")
    
    @classmethod
    def create(cls, node):
        """
        Create a proxy service instance based on a node object
        
        Args:
            node: Node object with proxy_type attribute
            
        Returns:
            ProxyServiceBase: An instance of a concrete proxy service
            
        Raises:
            ValueError: If the node has an unsupported proxy type
        """
        if not node:
            raise ValueError("Node cannot be None")
        
        if not node.proxy_type:
            # Default to nginx if not specified
            return cls.create_service('nginx')
        
        return cls.create_service(node.proxy_type)
    
    @classmethod
    def create_for_node_id(cls, node_id):
        """
        Create a proxy service instance for a node ID
        
        Args:
            node_id: ID of the node
            
        Returns:
            ProxyServiceBase: An instance of a concrete proxy service
            
        Raises:
            ValueError: If node not found or has an unsupported proxy type
        """
        node = Node.query.get(node_id)
        if not node:
            raise ValueError(f"Node with ID {node_id} not found")
        
        return cls.create(node)
    
    @classmethod
    def get_supported_proxy_types(cls):
        """
        Get a list of supported proxy types
        
        Returns:
            list: A list of supported proxy types
        """
        return list(cls._service_registry.keys())
    
    @classmethod
    def get_proxy_type_for_service(cls, service):
        """
        Get the proxy type for a service instance
        
        Args:
            service: Instance of a ProxyServiceBase subclass
            
        Returns:
            str: The proxy type for the service, or None if not found
        """
        for proxy_type, service_class in cls._service_registry.items():
            if isinstance(service, service_class):
                return proxy_type
        
        return None
    
    @classmethod
    def clear_instances(cls):
        """
        Clear all cached service instances
        This is mainly useful for testing and memory management
        """
        cls._service_instances = {}