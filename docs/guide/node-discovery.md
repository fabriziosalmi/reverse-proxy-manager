# Automatic Node Discovery

Reverse Proxy Manager supports automatic discovery of proxy nodes from a YAML configuration file, enabling seamless management of infrastructure at scale.

## How It Works

1. Nodes are defined in a YAML file (`config/nodes.yaml` by default)
2. When the application starts with auto-discovery enabled, it reads this file and adds/updates nodes
3. Discovered nodes are marked with the `is_discovered` flag in the database
4. Nodes can be auto-activated upon discovery (configurable)

## Enabling Auto-Discovery

Set the following environment variables:

\`\`\`bash
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=/path/to/custom/nodes.yaml  # Optional, defaults to config/nodes.yaml
AUTO_ACTIVATE_DISCOVERED_NODES=true  # Optional, defaults to true
\`\`\`

## YAML File Format

The `nodes.yaml` file should contain a list of node objects:

\`\`\`yaml
- name: cdn-node-1             # Required: Unique name to identify the node
  ip_address: 192.168.1.10     # Required: IPv4 or IPv6 address
  ssh_user: ubuntu             # Required: SSH username
  ssh_port: 22                 # Optional: SSH port (default: 22)
  ssh_key_path: /path/to/key   # Optional: Path to SSH private key
  ssh_password: password123    # Optional: SSH password (if not using key)
  nginx_config_path: /etc/nginx/conf.d  # Optional: Nginx config path
  nginx_reload_command: sudo systemctl reload nginx  # Optional: Command to reload Nginx
\`\`\`

## Manual Discovery

You can trigger node discovery manually using the CLI command:

\`\`\`bash
# Using default nodes.yaml location
./manage.py discover-nodes

# Specifying a custom YAML file
./manage.py discover-nodes --yaml-path=/path/to/nodes.yaml

# Disable auto-activation of discovered nodes
./manage.py discover-nodes --no-activate
\`\`\`
