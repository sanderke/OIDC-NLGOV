# Intro
* OAuth2 NL-Gov/iGov as basis
* TBD: based upon OpenID Connect iGov?
* Dutch Government & public domain
## Requirements Notation and Conventions
## Terminology
## Conformance


# Use case & context
* Intra & inter organisation
** C2G, B2G
** B2B, C2B not excluded
* IDs/attrs
* representation
** attrs representative
* Web, native
** native app as instance or through backend
* Service Intermediation (!)
* No active federation support
* MUST NOT self-issued
* E2E security

# Flow
## Access token as JWT Bearer
* access token, ID token, UserInfo and introspecton response at discretion for flexiblity & max interop

# Client / Relying Party profile
## Requests to the Authorization Endpoint (Authentication Request)
* private_key_jwt authentication
* intra-organisation PKIo
## Requests to the Token Endpoint
* claims parameter
## ID Tokens
## Request Objects
* prefered + signed
## Discovery
## Act/may_act alike = ref RFC 8693
* TBD: impersonisation+user or user+authorizations?
## Native/SPA, extra security measures
* see security considerations
## LoA =~ eIDAS
* RBA part of LoA
** Context based authentication = DV requested LoA

# OpenID Provider profile
## ID Tokens
## Pairwise Identifiers
* sectoral/public types
## UserInfo Endpoint
## Request Objects
## Vectors of Trust
* Not to be used, eIDAS, LoA preferred
## Authentication Context
## Discovery
## Dynamic Registration


# User Info
## Claims Supported
## Scope Profiles
## Claims Request
## Claims Response
## Claims Metadata


# Relation with 3rd party (Resource Servers)
## Service Intermediation
* RFC7800 cnf key/cert references
* requires registration of resource servers

# Special usage
## offline
* TBD: VWS, RvIG: input!

# Privacy considerations
* Encrypt BSN
* minimize scope, use RFC8693 token exchange to switch scopes

# Security considerations
## Source and quality/reliability attributes
* TBD: use aggregated/distributed claims?
* web-app security
* native app security

# Future updates
## Federations
* jar, par & rar

