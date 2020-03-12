# Abstract
The OpenID Connect protocol defines an identity federation system that allows
a relying party to request and receive authentication and profile information
about an end user.

This specification profiles the OpenID Connect protocol to increase baseline
security, provide greater interoperability, and structure deployments in a
manner specifically applicable to (but not limited to) government and public
service domains in The Netherlands.

This profile builds on top of, and inherits all properties of, the NL GOV 
Assurance profile for OAuth 2.0.

# Introduction
Government regulations for permitting users (citizens and non-citizens) online
access to government resources vary greatly from region to region. There is a
strong desire to leverage federated authentication and identity services for
public access to government resources online to reduce 'password fatigue',
increase overall account security, reduce cost, and provide reliable identity
assurances from established and trusted sources when applicable.

This specification aims to define an OpenID Connect profile that provides Dutch
governments with a foundation for securing federated access to public services
online.

## Requirements Notation and Conventions
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in 
[RFC 2119](https://openid.net/specs/openid-igov-openid-connect-1_0.html#RFC2119).

All uses of 
[JSON Web Signature (JWS)](https://openid.net/specs/openid-igov-openid-connect-1_0.html#RFC7515) 
and [JSON Web Encryption (JWE)](https://openid.net/specs/openid-igov-openid-connect-1_0.html#RFC7516) 
data structures in this specification utilize the JWS Compact Serialization or 
the JWE Compact Serialization; the JWS JSON Serialization and the JWE JSON
Serialization are not used.

## Terminology
This specification uses the terms "Access Token", "Authorization Code", 
"Authorization Endpoint", "Authorization Grant", "Authorization Server", 
"Client", "Client Authentication", "Client Identifier", "Client Secret", 
"Grant Type", "Protected Resource", "Redirection URI", "Refresh Token", 
"Resource Owner", "Resource Server", "Response Type", and "Token Endpoint" 
defined by OAuth 2.0, the terms "Claim Name", "Claim Value", and 
"JSON Web Token (JWT)" defined by JSON Web Token (JWT), 
and the terms defined by OpenID Connect Core 1.0.

* TODO functional terminology such as representation, eIDAS, etc.
* TODO abbreviations

## Conformance
* TBD: based upon OpenID Connect iGov?

This specification defines requirements for the following components:
- OpenID Connect 1.0 relying parties (also known as OpenID Clients)
- OpenID Connect 1.0 identity providers (also known as OpenID Providers)

The specification also defines features for interaction between these components:
- Relying party to identity provider

When an iGov-NL-compliant component is interacting with other iGov-NL-compliant 
components, in any valid combination, all components MUST fully conform to the 
features and requirements of this specification. All interaction with 
non-iGov-NL components is outside the scope of this specification.

An iGov-NL-compliant OpenID Connect IdP MUST support all features as described 
in this specification. A general-purpose IdP MAY support additional features 
for use with non-iGov-NL clients.

An iGov-NL-compliant OpenID Connect IdP MAY also provide iGov-NL-compliant 
OAuth 2.0 authorization server functionality. In such cases, the authorization 
server MUST fully implement the OAuth 2.0 iGov-NL profile. If an 
iGov-NL-compliant OpenID Connect IdP does not provide iGov-NL-compliant 
OAuth 2.0 authorization server services, all features related to interaction 
between the authorization server and protected resource are therefore OPTIONAL.

An iGov-NL-compliant OpenID Connect client MUST use all functions as described 
in this specification. A general-purpose client library MAY support additional 
features for use with non-iGov-NL IdPs.

# Use case & context
This profiles supports several use cases. Design choices within this profile have been made with these use cases under consideration.

The generic use case is a User with the intention to consume an online service of a Service Provider. As the Service requires authentication, this triggers the authentication process.

Authentication is provided in a federated manner. In other words, a Client system is relying upon another system for authentication.
Either a central IDP / OpenID Provider (OP) or a (distributed) network of OPs, a.k.a. a federation or scheme is being used. The ecosystem supported by the OP can either be a single organisation (intra organisational) or can be an interorganisational setting, through either bilateral or multilateral agreements.
In case a federation or scheme is being used, an Identity Broker may be applicable. Although this profile allows for usage in a federation, no explicit support for federations is _currently_ included.

The Service is offered by a (semi)governmental or public Service Provider. The use case therefor explicitly covers citizen to government (C2G) as well as business to government (B2G) contexts. This profile is not limited to C2G and B2G, nor intended to excluded consumer to business (C2B) and business to business (B2B) contexts, however additional considerations may be applicable in other contexts.

The Service Provider or Relying Party requests either an authenticated identifier, attributes or both from the OP. As target User audiences are diverse, multiple types of identifiers can be supported.

## Representation
This profile supports several use cases for representation, which applies when an End-User intends to consume an online Service that requires authentication on behalf of a Natural Person or Legal Entity (the Service Consumer). The End-User is a Natural Person, representing the Service Consumer through a representation relationship. The relationship has to be formalized and may be either a direct relationship, either voluntarily on legal grounds, or a chain of representation relationships. The formalization of these relationships is out of scope of this profile.

The Service is offered by a (semi)governmental or public Service Provider; example Use Cases include voluntary authorization, representative assigned by court order (guardian, administrator), statutory signatory (director, president), limited authorized signatory, etc.

This profile uses the delegation Use Case as specified in [RFC8693](https://tools.ietf.org/html/rfc8693) as a basis.

## Web and Native app
This profile supports both web as well as native applications.

For web applications, the web server of the Relying Party is always considered the Client. As this is a centrally managed server, this server is assumed to have a private key at its disposal.

For native applications two deployment modes are supported under this profile. Either the native application has a back-end system of the provider, where the back-end system is considered the Client. Or each individual installation is its own Client and registered as such. Native applications where the generic software package itself (in an _appstore_) is configured as a single Client, are explicitly prohibited under this profile.

Finally, hybrid forms of web- and native application are appearing as well. These are to be treated as either a web-application with a back-end server, or as a native application with individual "installations" as Client. It depends on the architecture and implementation which is applicable in a specific scenario.

This profile builds upon best practices for native applications, such as [RFC8252](https://tools.ietf.org/html/rfc8252), along with additional security and privacy considerations.

## Service Intermediation
* TODO FdK

## Misc
OpenID Connect Core supports self-issued OpenID Connect Provider. As the context of this profile is centered around (semi-)governemental and public domain use cases, some assurance on identity verifying will be required in almost every scenario. Therefore self-issued OpenID Providers MUST NOT be accepted by Relying Parties under this profile.

As the Dutch identity eco-system supports multiple Identity Providers (OpenID Providers), Identity Brokers are in common use. Brokers relieve Relying Parties of managing many connections to OPs, but every additional step introduces security risks and concern with regards to privacy. Among the privacy concerns is forming of a so-called hotspot, points were data collection can be concentrated.
To mitigate such risks, end-to-end security is considered throughout this profile. Controls such as signing, to assure integrity, and encryption, to strengthen confidentiality, will be encouraged to increase overall end-to-end security.

# Flow
* not in iGov, additional
* Authoriation code flow

## Access Token as JWT Bearer
This profile requires an Access Token to be in JWT form. This is in line with the underlying OAuth2 NL-Gov and iGov profiles.

Using a JWT formatted Access Token allows any Relying Party to consume and verify a token without the need for introspection, thus reducing the dependency on an interaction with an external endpoint. As a result this may reduce load and availability requirements on the OpenID Provider. Furthermore, it provides a more uniform format over Access Token, ID Token, Userinfo response and introspection response.

Note that ID Token en Userinfo response are primarily intended for the Client. The Access Token is primarily intended for consumption by a Resource Server. Introspection response is for usage by the requestor of an Introspection, which can be either a Client or Resource Server.
This profile does not directly place any constraints on the placement of claims in various tokens or response messages. Claims may be placed in any of the four tokens/response messages, unless explicitly specified otherwise. This allows for maximum freedom and interoperability.


# Client / Relying Party profile
## Requests to the Authorization Endpoint (Authentication Request)
The NL GOV Assurance profile for OAuth 2.0 profile specifies requirements for requests to Authorization Endpoints - for example, when to use the PKCE parameters to secure token exchange.

In addition to the requirements specified in Section 2.1.1 of the NL Gov OAuth2 profile, the following describes the supported OpenID Connect Authorization Code Flow parameters for use with NL Gov compatible IdPs.

Request Parameters:

client_id

> REQUIRED. Valid OAuth 2.0 Client Identifier. MUST have the value as obtained during registration. 

response_type

> REQUIRED. MUST be set to “code”.  

scope


>  REQUIRED. Indicates the attributes being requested. (See below) 

redirect_uri


>  REQUIRED. Indicates a valid endpoint where the client will receive the authentication response. MUST be an absolute HTTPS URL, pre-registered with the Authorization Server.

state


>  REQUIRED. Unguessable random string generated by the RP, used to protect against CSRF attacks. Must contain a sufficient amount of entropy to avoid guessing. Returned to the RP in the authentication response. 

nonce


>  REQUIRED. Unguessable random string generated by the client, used to protect against CSRF attacks. Must contain a sufficient amount of entropy to avoid guessing. Returned to the client in the ID Token. 

vtr


>  OPTIONAL. MUST be set to a value as described in Section 6.1 of Vectors of Trust. acr_values takes precedence over vtr. 

acr_values


>  OPTIONAL. Lists the acceptable LoAs for this authentication. See (below). 

code_challenge and code_challenge_method


>  OPTIONAL. See NL Gov OAuth2 profile. In case of using a native app as user-agent mandatory.

A sample request may look like:
```
https://idp-p.example.com/authorize?
 client_id=55f9f559-2496-49d4-b6c3-351a586b7484
 &nonce=cd567ed4d958042f721a7cdca557c30d
 &response_type=code
 &scope=openid+email
 &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 &state=2ca3359dfbfd0
 &acr_values=http%3a%2f%2feidas.europa.eu%2fLoA%2fsubstantial
```


* iGov: usable; vtr not applicable (acr\_values for LoA preferred)
* private\_key\_jwt authentication
** mTLS (RFC-to-be-8705) optional alternative
* intra-organisation PKIo, as in OAuth NL-Gov profile
* claims parameter

## Requests to the Token Endpoint
* iGov: usable
* mTLS (RFC-to-be-8705) as alternative client authentication method, influences parameters client\_assertion
* relation to token Exchange (RFC8693); limiting scope, switching of audiences, service intermediation (dienstbemiddeling)

## ID Tokens
* iGov: usable
** acr required

### Act/may\_act alike = ref RFC 8693
* mandatory processing of "act" and "may\_act\_on\_behalf" like claims
* TBD: impersonisation+user or user+authorizations?

## Request Objects
* iGov: usable
* preferred + signed

## Discovery
* iGov: usable
* SHOULD for client; reduce manual labour with risk of config mistakes
* guidelines for caching duration and handling updates/changes
** include JWK_uri content updates
* relation to acceptable methods and algorithms

## Registration
* not in iGov, additional
* MAY/SHOULD for Client; reduce manual labour with risk of config mistakes
* TBD: details of minimal registraton parameters?
* relation to RFC7591 OAuth 2.0 Dynamic Client Registration
* MAY support RFC7592 OAuth 2.0 Dynamic Client Registration Management Protocol 
* relation to acceptable methods and algorithms

## Native/SPA, extra security measures
* not in iGov, additional
* see security considerations


# OpenID Provider profile
* TBD: add section on access token? (on top of / in relation to OAuth2)

## ID Tokens
* iGov: usable
* vot and vtr not applicable (acr for LoA preferred)
### Act/may\_act alike = ref RFC 8693
* TBD: impersonisation+user or user+authorizations?

## Pairwise Identifiers
* iGov: usable
* sectoral/public types

## UserInfo Endpoint
* iGov: usable

## Request Objects
* iGov: usable

## Vectors of Trust
* iGov: not well suited
* Not to be used, eIDAS, LoA preferred

## Authentication Context
* iGov: somewhat usable
* recommended: use eIDAS values when applicable
* allow other forms where eIDAS not applicable
* add note on RBA part of LoA; risk based authentication should be integral part of LoA framework
** Context based authentication = DV requested LoA
* avoid amr, use acr instead

## Discovery
* iGov: usable; (URL = discovery endpoint = identifier of issuer, mandatory?)
* MUST support by OP
* guidelines for caching duration and handling updates/changes
** include JWK_uri content updates
* relation to acceptable methods and algorithms

## Dynamic Registration
* iGov: usable
* SHOULD (Strongly recommended!) support by OP
** mandatory when native instance is client

# User Info
* iGov: usable

## Claims Supported
* iGov: usable
* add syntax of attribute(names)
* add default 'Dutch' attributes in relation to BRP
** Reference to ISA<sup>2</sup> for common semantics
* applicable (recursively) when dealing with representation (act / may\_act\_on\_behalf alike) as well

## Scope Profiles
* iGov: usable
** note that NL often _is_ able to provide a single identifier for all citizens based on an authoritative register of citizens
** 'profile' profile is very wide, from privacy/data protection point of view
** doc profile not well suited for NL

## Claims Request
* iGov: usable
* TBD: claims parameter has benefits functionally/security wise, support may be less widespread though

## Claims Response
* iGov: mostly irrelevant, as doc profile less usefull in NL

## Claims Metadata
* iGov: usable
* add source/time of attribute for quality/reliability of attributes, fits well with aggregated/distributed claims, limited supported in tools though
* criteria for acceptance up to relying party, beyond scope of this profile

# Relation with 3rd party (Resource Servers)
## Service Intermediation
* not part of iGov
* RFC7800 cnf key/cert references
* requires registration of resource servers, for introspection (move up to OAuth profile?)


# Special usage
## offline
* not part of iGov
* TBD: VWS, RvIG: input!


# Privacy considerations
* iGov: usable
* Encrypt BSN and other identifiers
** either full token, or using aggregated/distributed claims
* minimize scope, use RFC8693 token exchange to switch scopes
* minimize use of attributes, in general

# Security considerations
* iGov: usable
** add NCSC TLS guidelines, SHOULD 'good', MAY 'sufficient', SHOULD NOT 'phase out'
## algorithms
* Default and acceptable algorithms for signing and encryption
** RS256 MUST, PS256 SHOULD (preferred)
** A256GCM SHOULD (preferred)
** TODO: others

## web-app security
* HSTS
* CSP
* CORS
* SRI
* Cookie security
* other anti-XSS/CSRF techniques
* short-lived sessions
* utilize webcrypto API
## native app / SPA / JS security
* RFC8252
** Strict in-app browser only!
** HTTPS scheme URL handler only
* HSTS
* CSP
* CORS
* SRI
* Cookie security
* other anti-XSS/CSRF techniques
* short-lived sessions
** use refresh tokens


# Future updates
* not part of iGov

## Federations
This profile acknowledges that federations are widely in use, in particular among (semi-)governmental and public domain. However, no specific support or requirements for federations are included in this version of this profile.
The OpenID Foundation is currently drafting a specification for explicit support of federations using OpenID Connect. Future updates to this profile are likely to adopt this specification once finalized. See [Federation at the OpenID Foundation](https://openid.net/tag/federation/).

## Other features
A RFC for Access Tokens in JWT format is being drafted in the OAuth2 working group at IETF. Future updates to this profile are likely to seek interoperability with such RFC once finalized. See [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-access-token-jwt/).

A RFC for Secured (signed and/or encrypted) Authorization Requests is being drafted in the OAuth2 working group at IETF.
Similarly, a RFC for pushing Authorization Requests to relieve Clients from hosting `request_uri` based requests is being drafted in the OAuth2 working group at IETF.
Both practices are already part of the OpenID Connect Core specifications.
Future updates to this profile are likely to seek interoperability with these RFCs once finalized.

* rar; work in progress @ IETF (OAuth2)


#  Appendix Notices
* (C) copyright OIDF (!), ... TODO
