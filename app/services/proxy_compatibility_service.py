import json
from app.models.models import Node, Site

class ProxyCompatibilityService:
    """Service to check compatibility of site features across different proxy types"""
    
    # Feature support matrix for different proxy types
    # True: Fully supported
    # False: Not supported
    # "limited": Limited support
    FEATURE_SUPPORT = {
        "nginx": {
            "waf": True,
            "cache": True,
            "rate_limiting": True,
            "geoip": True,
            "websocket": True,
            "custom_headers": True,
            "url_rewriting": True,
            "auto_ssl": "limited",
            "http3": "limited"
        },
        "caddy": {
            "waf": "limited",
            "cache": "limited",
            "rate_limiting": "limited",
            "geoip": True,
            "websocket": True,
            "custom_headers": True, 
            "url_rewriting": True,
            "auto_ssl": True,
            "http3": True
        },
        "traefik": {
            "waf": "limited",
            "cache": "limited",
            "rate_limiting": True,
            "geoip": "limited",
            "websocket": True,
            "custom_headers": True,
            "url_rewriting": "limited",
            "auto_ssl": True,
            "http3": "limited"
        }
    }
    
    @staticmethod
    def check_feature_compatibility(site_features, proxy_types):
        """
        Check if the site features are compatible with the selected proxy types
        
        Args:
            site_features: List of features used by the site
            proxy_types: List of proxy types to check against
            
        Returns:
            dict: Compatibility information
        """
        compatibility = {
            "is_compatible": True,
            "warnings": [],
            "feature_matrix": {}
        }
        
        # Create a feature matrix to show compatibility of each feature with each proxy type
        for feature in site_features:
            compatibility["feature_matrix"][feature] = {}
            for proxy_type in proxy_types:
                if proxy_type not in ProxyCompatibilityService.FEATURE_SUPPORT:
                    compatibility["warnings"].append(f"Unknown proxy type: {proxy_type}")
                    compatibility["is_compatible"] = False
                    compatibility["feature_matrix"][feature][proxy_type] = False
                    continue
                
                if feature not in ProxyCompatibilityService.FEATURE_SUPPORT[proxy_type]:
                    compatibility["warnings"].append(
                        f"Unknown feature '{feature}' for proxy type '{proxy_type}'"
                    )
                    compatibility["is_compatible"] = False
                    compatibility["feature_matrix"][feature][proxy_type] = False
                    continue
                
                support = ProxyCompatibilityService.FEATURE_SUPPORT[proxy_type][feature]
                compatibility["feature_matrix"][feature][proxy_type] = support
                
                # If support is limited or not available, add a warning
                if support == "limited":
                    compatibility["warnings"].append(
                        f"'{feature}' has limited support in '{proxy_type}'"
                    )
                elif not support:
                    compatibility["warnings"].append(
                        f"'{feature}' is not supported in '{proxy_type}'"
                    )
                    compatibility["is_compatible"] = False
        
        return compatibility
    
    @staticmethod
    def get_site_features(site):
        """
        Determine the features used by a site
        
        Args:
            site: Site object
            
        Returns:
            list: List of features used by the site
        """
        features = []
        
        # Core features
        if site.protocol == 'https':
            features.append('auto_ssl')
        
        if site.use_waf:
            features.append('waf')
        
        if site.enable_cache:
            features.append('cache')
        
        if site.use_geoip:
            features.append('geoip')
        
        # Check for websocket support in custom config
        if (site.custom_config and 
            ('upgrade' in site.custom_config.lower() or 'websocket' in site.custom_config.lower())):
            features.append('websocket')
        
        # Check for rate limiting
        if hasattr(site, 'waf_rate_limiting_enabled') and site.waf_rate_limiting_enabled:
            features.append('rate_limiting')
        
        # Check for custom headers
        if (site.custom_config and 
            ('add_header' in site.custom_config.lower() or 'header' in site.custom_config.lower())):
            features.append('custom_headers')
        
        # Check for URL rewriting
        if (site.custom_config and 
            ('rewrite' in site.custom_config.lower() or 'return 301' in site.custom_config.lower())):
            features.append('url_rewriting')
        
        # Check for HTTP/3 support
        if hasattr(site, 'enable_http3') and site.enable_http3:
            features.append('http3')
        
        return features
    
    @staticmethod
    def check_nodes_compatibility(site, node_ids):
        """
        Check compatibility of a site across the selected nodes
        
        Args:
            site: Site object
            node_ids: List of node IDs
            
        Returns:
            dict: Compatibility information
        """
        # Get proxy types for the selected nodes
        nodes = Node.query.filter(Node.id.in_(node_ids)).all()
        proxy_types = [node.proxy_type for node in nodes]
        
        # Get features used by the site
        site_features = ProxyCompatibilityService.get_site_features(site)
        
        # Check compatibility
        compatibility = ProxyCompatibilityService.check_feature_compatibility(
            site_features, proxy_types
        )
        
        # Add node information
        compatibility["nodes"] = {}
        for node in nodes:
            compatibility["nodes"][node.id] = {
                "name": node.name,
                "proxy_type": node.proxy_type
            }
        
        return compatibility
    
    @staticmethod
    def get_proxy_type_info(proxy_type):
        """
        Get information about a proxy type's capabilities
        
        Args:
            proxy_type: Name of the proxy type
            
        Returns:
            dict: Information about the proxy type's capabilities
        """
        if proxy_type not in ProxyCompatibilityService.FEATURE_SUPPORT:
            return {"error": f"Unknown proxy type: {proxy_type}"}
        
        return {
            "proxy_type": proxy_type,
            "features": ProxyCompatibilityService.FEATURE_SUPPORT[proxy_type]
        }
    
    @staticmethod
    def get_feature_info(feature):
        """
        Get information about a feature across all proxy types
        
        Args:
            feature: Name of the feature
            
        Returns:
            dict: Information about the feature's support across proxy types
        """
        result = {
            "feature": feature,
            "support": {}
        }
        
        for proxy_type, features in ProxyCompatibilityService.FEATURE_SUPPORT.items():
            if feature in features:
                result["support"][proxy_type] = features[feature]
            else:
                result["support"][proxy_type] = False
        
        return result