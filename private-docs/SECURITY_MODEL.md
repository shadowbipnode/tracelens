# TraceLens security model

## Purpose

TraceLens collects and correlates publicly available domain intelligence while minimizing operational, privacy, legal, and source-abuse risk.

## Collection boundary

Allowed:

- public DNS queries
- public WHOIS lookups
- certificate transparency queries
- web archive metadata queries
- search of existing public URLScan observations
- Shodan passive DNS queries
- Censys metadata queries for IPs already discovered in DNS

Not allowed:

- port scanning
- vulnerability scanning
- direct service fingerprinting
- directory or subdomain brute forcing
- authentication attempts
- credential testing
- exploitation
- target web-page requests

## Evidence model

Observed facts are normalized source values.

Correlated findings are deterministic relationships between observed entities.

Every derived fingerprint and correlation must contain:

- confidence
- reasoning
- evidence references

Unsupported conclusions are omitted.

## Failure isolation

Collectors:

- use bounded timeouts
- validate response structure
- classify errors
- avoid exposing credentials
- return partial normalized data when available
- never terminate the remaining collection sequence

Derived sections are independently guarded. A builder failure is recorded in `derivation_errors`; raw collector data and other workspace views remain available.

## Secrets

Optional provider credentials are supplied through environment variables or an ignored local `.env` file. Credentials must not be committed, logged, or copied into report JSON.

## Storage

Allowed:

- public collector responses
- scan metadata
- structured errors
- derived findings and relationships
- local analyst notes when that feature is implemented

Forbidden:

- plaintext credentials
- access tokens
- cookies
- private credential dumps
- leaked passwords

SQLite is local by default. Operators are responsible for filesystem access and report retention.

## Source safety

Collection is sequential and bounded. URLScan is search-only. Censys receives at most ten DNS-discovered addresses and retains at most fifty normalized services per host. crt.sh and Wayback retries are limited.

## Analyst interpretation

Historical observations do not prove current state. Provider signatures describe matching passive evidence, not legal ownership. Moderate-confidence matches should be reviewed against cited evidence before external use.
