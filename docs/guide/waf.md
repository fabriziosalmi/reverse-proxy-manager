# Web Application Firewall (WAF)

The Reverse Proxy Manager includes a comprehensive Web Application Firewall (WAF) system based on ModSecurity to protect your sites from common web vulnerabilities.

## Protection Levels

Three protection levels are available:

- **Basic**: Essential protection against common web attacks with minimal false positives
- **Medium**: Enhanced protection with stricter rules (paranoia level 3)
- **Strict**: Maximum security with comprehensive rule sets (paranoia level 4)

## Configuration Options

- **Request Size Limits**: Set maximum allowed size for client requests (1-100 MB)
- **Request Timeouts**: Configure timeouts for processing requests (10-300 seconds)
- **Tor Exit Node Blocking**: Option to block requests from known Tor exit nodes
- **Rate Limiting**: Restrict the number of requests per IP address with configurable:
  - Requests per minute (10-10000)
  - Burst size (10-20000)
- **Custom Rules**: Add custom ModSecurity compatible directives

## Sample Custom Rules

```
# Block specific user agent
SecRule REQUEST_HEADERS:User-Agent "badbot" "id:1000,phase:1,deny,status:403,log,msg:'Blocked Bad Bot'"

# Block specific IP range
SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:1001,phase:1,deny,status:403,log,msg:'Blocked IP Range'"

# Block specific URI path
SecRule REQUEST_URI "@contains /admin/backup" "id:1002,phase:1,deny,status:403,log,msg:'Blocked sensitive URI'"
```
