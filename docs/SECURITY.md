# Security behavior

TraceLens performs public-source lookups only.

Allowed collection:

- DNS
- WHOIS
- certificate transparency
- web archive metadata
- existing URLScan observations
- Shodan passive DNS
- Censys metadata for DNS-discovered IPs

TraceLens does not scan ports, request target web pages, enumerate paths, authenticate, exploit services, or test credentials.

Collectors use bounded requests, timeouts, structured errors, and sequential orchestration. Optional credentials are read from environment variables and are not copied into reports.
