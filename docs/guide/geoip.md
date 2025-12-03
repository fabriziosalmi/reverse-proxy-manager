# Geographic Access Control (GeoIP)

The application offers country-based access control at two levels:

## Nginx Level GeoIP (Per Site)

- Configure per site in the site settings
- Two operation modes:
  - **Blacklist**: Block specific countries
  - **Whitelist**: Allow only specific countries
- Uses ISO 3166-1 alpha-2 country codes (e.g., US, CA, UK, DE)

## IP Tables Level GeoIP (Node-wide)

- Admin-only feature configured at the node level
- Affects all sites on the node
- Higher performance than Nginx-level filtering
- Managed through the node's country blocking interface
