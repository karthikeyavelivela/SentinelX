# SentinelX Legal and Usage Boundaries

## What SentinelX does

SentinelX is an external exposure intelligence tool for authorized security assessment and service delivery.  
It collects publicly observable and low-impact network evidence, then produces structured and executive-grade reports for client-facing delivery.

## What SentinelX does not do

SentinelX is not an exploit framework. It does not perform credential brute force, malware delivery, privilege escalation, destructive actions, or payload-driven exploit attempts against application logic.

## Passive checks in SentinelX

The following checks are passive or passive-intelligence style:

- Certificate transparency discovery through `crt.sh`
- DNS record collection (A, MX, TXT, CNAME, SPF, DMARC)
- TLS certificate metadata retrieval (issuer, validity, protocol metadata)

These checks observe externally available infrastructure data and certificate metadata.

## Active checks in SentinelX

The following checks are active and involve direct interaction with target systems:

- HTTPS requests for response/header and technology fingerprinting
- Favicon HTTP retrieval for hash fingerprinting
- Lightweight TCP probing of common service ports

These checks are intentionally limited in scope, but they are still active interactions with target infrastructure.

## Authorization requirement

Do not run SentinelX on systems you do not own or do not have explicit written permission to assess.  
Written authorization should define scope, timing, and point-of-contact.

## Legal references

Use of this tool may be regulated by local and international law, including:

- India: Information Technology Act, 2000 (and amendments)
- United States: Computer Fraud and Abuse Act (CFAA)
- United Kingdom: Computer Misuse Act (CMA)

You are responsible for legal compliance in every jurisdiction where scans are initiated, routed, or delivered.

## Intended use

SentinelX is designed for authorized security assessment, exposure intelligence reporting, and commercial service delivery under valid contractual authorization.
