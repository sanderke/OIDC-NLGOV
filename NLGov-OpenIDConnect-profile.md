# Abstract
The OpenID Connect protocol defines an identity federation system that allows
a Relying Party to request and receive authentication and profile information
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
document are to be interpreted as described in [[rfc2119]].

All uses of "JSON Web Signature (JWS)" [[rfc7515]] and "JSON Web Encryption
(JWE)" [[rfc7516]] data structures in this specification utilize the JWS
Compact Serialization or the JWE Compact Serialization; the JWS JSON
Serialization and the JWE JSON Serialization are not used.

## Terminology
This specification uses the terms "Access Token", "Authorization Code", 
"Authorization Endpoint", "Authorization Grant", "Authorization Server", 
"Client", "Client Authentication", "Client Identifier", "Client Secret", 
"Grant Type", "Protected Resource", "Redirection URI", "Refresh Token", 
"Resource Owner", "Resource Server", "Response Type", and "Token Endpoint" 
defined by OAuth 2.0, the terms "Claim Name", "Claim Value", and 
"JSON Web Token (JWT)" defined by JSON Web Token (JWT), 
and the terms defined by OpenID Connect Core 1.0.

- "Browser-based application" (from [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps))
* TODO functional terminology such as representation, eIDAS, etc.
* TODO abbreviations

## Conformance
This specification defines requirements for the following components:
- OpenID Connect 1.0 Relying Parties (also known as OpenID Clients)
- OpenID Connect 1.0 Identity Providers (also known as OpenID Providers)

The specification also defines features for interaction between these components:
- Relying Party to Identity Provider

This profile is based upon the International Government Assurance Profile (iGov) for 
OpenID Connect 1.0 [iGOV.OpenID] as published by the OpenID Foundation 
(https://openid.net/foundation/). It should be considered a fork of this profile, as 
the iGov profile is geared more towards a United States context and the Netherlands 
towards a European Union context.

When an iGov-NL-compliant component is interacting with other iGov-NL-compliant 
components, in any valid combination, all components MUST fully conform to the 
features and requirements of this specification. All interaction with 
non-iGov-NL components is outside the scope of this specification.

An iGov-NL-compliant OpenID Connect Identity Provider MUST support all features as described 
in this specification. A general-purpose Identity Provider MAY support additional features 
for use with non-iGov-NL clients.

An iGov-NL-compliant OpenID Connect Identity Provider MAY also provide iGov-NL-compliant 
OAuth 2.0 authorization server functionality. In such cases, the authorization 
server MUST fully implement the OAuth 2.0 iGov-NL profile. If an 
iGov-NL-compliant OpenID Connect Identity Provider does not provide iGov-NL-compliant 
OAuth 2.0 authorization server services, all features related to interaction 
between the authorization server and protected resource are therefore OPTIONAL.

An iGov-NL-compliant OpenID Connect client MUST use all functions as described 
in this specification. A general-purpose client library MAY support additional 
features for use with non-iGov-NL OpenID Connect Identity Providers.

# Use Case & context
This profiles supports several Use Cases. Design choices within this profile have been made with these Use Cases under consideration.

The generic Use Case is an End-User with the intention to consume an online service of a Service Provider. As the Service requires authentication, this triggers the authentication process.

Authentication is provided in a federated manner. In other words, a Client system is relying upon another system for authentication.
Either a central Identity Provider (IdP) / OpenID Provider (OP) or a (distributed) network of OpenID Providers, a.k.a. a federation or scheme is being used. The ecosystem supported by the OpenID Provider can either be a single organisation (intra organisational) or can be an interorganisational setting, through either bilateral or multilateral agreements.
In case a federation or scheme is being used, an Identity Broker may be applicable. Although this profile allows for usage in a federation, no explicit support for federations is _currently_ included.

The Service is offered by a (semi)governmental or public Service Provider. The Use Case therefore explicitly covers citizen to government (C2G) as well as business to government (B2G) contexts. This profile is not limited to C2G and B2G, nor intended to excluded consumer to business (C2B) and business to business (B2B) contexts, however additional considerations may be applicable in other contexts.

The Service Provider or Relying Party requests either an authenticated identifier, attributes or both from the OP. As target User audiences are diverse, multiple types of identifiers can be supported.

## Representation
This profile supports several Use Cases for representation, which apply when an End-User intends to consume an online Service that requires authentication on behalf of a Natural Person or Legal Entity (the Service Consumer). The End-User is a Natural Person, representing the Service Consumer through a representation relationship. The relationship has to be formalized and may be either a direct relationship, either voluntarily on legal grounds, or a chain of representation relationships. The formalization of these relationships is out of scope of this profile.

The Service is offered by a (semi)governmental or public Service Provider; example Use Cases include voluntary authorization, representative assigned by court order (guardian, administrator), statutory signatory (director, president), limited authorized signatory, etc.

## Service Intermediation
* TODO FdK

## Token Exchange
This profile supports the exchanging of security tokens as specified in [[RFC8693]]. This invoves 
exchanging an earlier obtained token into a differently scoped token or an entirely different kind 
of token.

Use Cases include, but are not limited by:
- Exchanging a token with a specific audience or represented Service Consumer into a token with a
different audience or represented Service Consumer;
- A Service Intermediary exchanging a token that it obtained earlier into a token specific to a service that it intermediates; and
- An OAuth 2.0 Resource Server exchanging an earlier obtained access token into a new token that
is appropriate to include in a call to a backend service.

## Misc
OpenID Connect Core supports self-issued OpenID Connect Provider. As the context of this profile is centered around (semi-)governemental and public domain Use Cases, some assurance on identity verifying will be required in almost every scenario. Therefore self-issued OpenID Providers MUST NOT be accepted by Relying Parties under this profile.

As the Dutch identity eco-system supports multiple Identity Providers (OpenID Providers), Identity Brokers are in common use. Brokers relieve Relying Parties of managing many connections to OPs, but every additional step introduces security risks and concern with regards to privacy. Among the privacy concerns is forming of a so-called hotspot, points were data collection can be concentrated.
To mitigate such risks, end-to-end security is considered throughout this profile. Controls such as signing, to assure integrity, and encryption, to strengthen confidentiality, will be encouraged to increase overall end-to-end security.

# Flow
This profile requires that authentication is performed using the Authorization Code Flow, in where all tokens are returned from the Token Endpoint.

## Access Token as JWT Bearer
This profile requires an Access Token to be in JWT form. This is in line with the underlying OAuth2 NL-Gov and iGov profiles.

Using a JWT formatted Access Token allows any Relying Party to consume and verify a token without the need for introspection, thus reducing the dependency on an interaction with an external endpoint. As a result this may reduce load and availability requirements on the OpenID Provider. Furthermore, it provides a more uniform format over Access Token, ID Token, Userinfo response and introspection response.

Note that ID Token en Userinfo response are primarily intended for the Client. The Access Token is primarily intended for consumption by a Resource Server. Introspection response is for usage by the requestor of an Introspection, which can be either a Client or Resource Server.
This profile does not directly place any constraints on the placement of claims in various tokens or response messages. Claims may be placed in any of the four tokens/response messages, unless explicitly specified otherwise. This allows for maximum freedom and interoperability.


# Client / Relying Party profile

## Client types
This profile supports several types of Client applications to which specific design considerations related to security and platform capabilities apply. This profile supports and provides specific security and privacy considerations for the following types of Client applications:

- **Web applications** are applications that run on a web server. Web applications are capable of securely authenticating themselves and of maintaining the confidentiality of secrets (e.g. client credentials and tokens) and are therefore considered *confidential* clients (OAuth 2.0 [[RFC6749]], [Section 2.1](https://tools.ietf.org/html/rfc6749#section-2.1)).
The iGov profile for OAuth 2.0 identifies two types of Web applications: *Full clients* act on behalf of a Resource Owner and *Direct Access clients* act on behalf of themselves (e.g. those clients that facilitate bulk transfers). The scope of this profile is limited to *Full clients*.
- **Browser-based applications** are applications that are dynamically downloaded and executed in a web browser that are also sometimes referred to as *user-agent-based applications* or *single-page applications*. Browser-based applications are not capable of maintaining the confidentiality of secrets and therefore vulnerable to several types of attacks, including XSS, CSRF and OAuth token theft. Browser-based applications are considered *public* clients (OAuth 2.0 [[RFC6749]], [Section 2.1](https://tools.ietf.org/html/rfc6749#section-2.1)).
- **Native applications** are applications installed and executed on the device used by the resource owner (i.e. desktop applications, native mobile applications). Native applications are not capable of maintaining the confidentiality of client credentials, but can sufficiently protect dynamically issued credentials such as tokens. Native applications are considered *public* clients, except when they are provisioned per-instance secrets via mechanisms like Dynamic Client Registration (OAuth 2.0 [[RFC6749]], [Section 2.1](https://tools.ietf.org/html/rfc6749#section-2.1)).
- **Hybrid applications** are applications implemented using web-based technology but distributed as a native app; these are considered equivalent to native applications for the purpose of this profile.

## Requests to the Authorization Endpoint (Authentication Request)
The NL GOV Assurance profile for OAuth 2.0 profile specifies requirements for requests to Authorization Endpoints - for example, when to use the PKCE parameters to secure token exchange.

Confidential clients (Web applications and Native clients with per-instance provisioned secrets) as defined above MUST authenticate to the authorization server using a JWT assertion as defined by the "JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants" [[rfc7523]] using only the private\_key\_jwt method defined in [OpenID Connect Core] [OpenID.Core].
In case of a mutual TLS connection (mTLS) between the client and the server, the JWT assertion can be omitted.

In case the Authorization Server, Resource Server and client are not operated under responsibility of the same organisation, each party MUST use PKIoverheid certificates with OIN. The PKIoverheid certificate MUST be included either as a x5c or as x5u parameter, as per [[rfc7517]] §4.6 and 4.7. Parties SHOULD at least support the inclusion of the certificate as x5c parameter, for maximum interoperability. Parties MAY agree to use x5u, for instance for communication within specific environments.

In addition to the requirements specified in Section 2.1.1 of the NL Gov OAuth2 profile, the following describes the supported OpenID Connect Authorization Code Flow parameters for use with NL Gov compatible Identity Providers.

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


>  REQUIRED. Unguessable random string generated by the Relying Party, used to protect against CSRF attacks. Must contain a sufficient amount of entropy to avoid guessing. Returned to the Relying Party in the authentication response. 

nonce


>  REQUIRED. Unguessable random string generated by the client, used to protect against CSRF attacks. Must contain a sufficient amount of entropy to avoid guessing. Returned to the client in the ID Token. 


vtr


>  OPTIONAL. MUST be set to a value as described in Section 6.1 of Vectors of Trust. acr_values takes precedence over vtr. 

acr_values


>  OPTIONAL. Lists the acceptable LoAs for this authentication. See (below). 

code_challenge and code_challenge_method


>  OPTIONAL. See NL Gov OAuth2 profile. In case of using a native app as user-agent mandatory.

claims

> OPTIONAL. This parameter is used to request specific Claims. The value is a JSON object listing the requested Claims.

client_assertion_type

> Must  MUST be set to urn:ietf:params:oauth:client-assertion-type:jwt-bearer.

client_assertion

> The value of the signed client authentication JWT generated as described below. The Relying Party must generate a new assertion JWT for each call to the token endpoint. 



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
In addition to the requirements specified in Section 2.3.1 of the NL Gov OAuth2 profile, the following claims MUST be included:
The following parameters are specified:

grant_type
> MUST be set to authorization_code.
 
code
> The value of the code parameter returned in the authorization response.

client_assertion_type
> MUST be set to urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
 
client_assertion
> The value of the signed client authentication JWT generated as described below. The Relying Party must generate a new assertion JWT for each call to the token endpoint. 

In case of a mutual TLS connection (mTLS) between the client and the server, the JWT assertion can be omitted.

* iGov: usable
* mTLS (RFC8705) as alternative client authentication method, influences parameters client\_assertion

## ID Tokens
All clients MUST validate the signature of an ID Token before accepting it
using the public key of the issuing server, which is published in JSON Web Key
(JWK) format. ID Tokens MAY be encrypted using the appropriate key of the
requesting client.

Clients MUST verify the following in received ID tokens:

iss

>    The `issuer` Claim is the Uniform Resource Locater (URL) of the expected issuer.

aud

>    The `audience` Claim contains the client ID of the client.

exp, iat, nbf

>    The `expiration`, `issued at`, and `not before` timestamps for the token are dates (integer number of seconds since from 1970-01-01T00:00:00Z UTC) within acceptable ranges.

acr

>    The Level of Assurance received in the `acr` Claim is at least the Level of Assurance requested. See "Authentication Context" for applicable values.

represents

>    in case Representation is applicable, the `represents` Claim provides information about the effective authorization for the acting party.

### Representation
In Use Cases where Representation is applicable, representation relations are explicitly mentioned in the form of a `represents` Claim, analogous to the Delegation Semantics specified in [[RFC 8693]].

As such, all clients MUST process `represents` claims used, in case Representation is applicable.

This profile specifies representation relations in ID Tokens as follows:
- The End-User is always mentioned in the `sub` Claim;
- The represented Service Consumer is mentioned in the `represents` Claim.
- In case a chain representation is applicable, the representation chain is represented as a series of nested `represents` Claims with the represented Service Consumer listed as the deepest nested `represents` Claim.

A sample chain representation may look like:

      {
        /* End user */
        "sub": "RKyL<<end_user>>pEVr1L",
        "sub_id_type": "urn:nl-eid-gdi:1.0:id:pseudonym",
        "represents": {
          /* Intermediary in representation chain */
          "sub": "q5r5sd8ffY",
          "sub_id_type": "urn:nl-eid-gdi:1.0:id:pseudonym",
          "represents": {
            /* Service Consumer */
            "sub": "4Yg8u72NxR",
            "sub_id_type": "urn:nl-eid-gdi:1.0:id:pseudonym",
          }
        }
      }

## Request Objects
Clients MAY optionally send requests to the authorization endpoint using the
request or request_uri parameter as defined by OpenID Connect. 
The use of the request_uri is preferred because of browser limits and network latency

Request objects MUST be signed by the client's registered key. Request objects MAY be 
encrypted to the authorization server's public key.

* iGov: usable
* preferred + signed

## Token Exchange
If the OpenID Provider is acting as an Security Token Service (STS) as specified in [[RFC8693]],
then the Token Exchange Request and Response MUST be in accordance with
that specification (see section 2), using the extension grant type
*"urn:ietf:params:oauth:grant-type:token-exchange"*.

## Discovery
Client SHOULD use OpenID Provider discovery to avoid manual configuration and risk of mistakes
Clients and protected resources SHOULD cache OpenID Provider metadata once an
OpenID Provider has been discovered and used by the client. 

Relying Parties and other Clients use the public keys made available from the jwks endpoint to 
validate the signature on tokens. The OIDC spec recommends using the HTTP Cache-Control Header 
option and the max-age directive to inform clients how long they can cache the public keys for 
before returning to the jwks_uri location to retrieve replacement keys from the Identity Provider.

To rotate keys, the decrypting party can publish new keys at its jwks_uri location and 
remove from the JWK Set those that are being decommissioned. The jwks_uri SHOULD include a 
Cache-Control header in the response that contains a max-age directive, which enables the 
encrypting party to safely cache the JWK Set and not have to re-retrieve the document for every 
encryption event. 
The decrypting party SHOULD 
remove decommissioned keys from the JWK Set referenced by jwks_uri but retain them internally 
for some reasonable period of time, coordinated with the cache duration, to facilitate a smooth 
transition between keys by allowing the encrypting party some time to obtain the new keys. 
The cache duration SHOULD also be coordinated with the issuance of new signing keys.
Please refer to [Algorithms](#algorithms) for more information on cryptographic
algorithms and keys.

* iGov: usable
* SHOULD for client; reduce manual labour with risk of config mistakes
* guidelines for caching duration and handling updates/changes
** include JWK_uri content updates

## Registration
All Clients MUST register with the Authorization Server.

Native Clients MUST either be provisioned a unique per-instance client identifier or be 
registered as *public* clients by using a common client identifier and use PKCE to 
protect calls to the token endpoint.

Browser-based Clients MUST be registered as *public* clients and use PKCE to protect calls to the token endpoint.

Clients SHOULD use Dynamic Registration as per [[rfc7591]] to reduce manual
labor and the risks of configuration errors. Dynamic Client Registration
Management Protocol [[rfc7592]] MAY be used by clients.
An initial access token is REQUIRED for making the client registration request. 
The client metadata MUST use the `authorization_code` and SHOULD use `jwks_uri` values.
The use of `subject_type` `pairwise` is highly recommended(?)

An example of a client registration request:
  
    POST /connect/register HTTP/1.1
    Content-Type: application/json
    Accept: application/json
    Host: server.example.com
    Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...

    {
      "application_type": "web",
      "redirect_uris":
        ["https://client.example.org/callback",
        "https://client.example.org/callback2"],
      "client_name": "My Example",
      "subject_type": "pairwise",
      "sector_identifier_uri":
        "https://other.example.net/file_of_redirect_uris.json",
      "token_endpoint_auth_method": "client_secret_basic",
      "jwks_uri": "https://client.example.org/my_public_keys.jwks",
      "userinfo_encrypted_response_alg": "RSA1_5",
      "userinfo_encrypted_response_enc": "A128CBC-HS256",
      "contacts": ["mary@example.org"],
    }

* not in iGov, additional
* MAY/SHOULD for Client; reduce manual labour with risk of config mistakes
* TBD: details of minimal registraton parameters?
* relation to RFC7591 OAuth 2.0 Dynamic Client Registration
* MAY support RFC7592 OAuth 2.0 Dynamic Client Registration Management Protocol 

Please refer to [Algorithms](#algorithms) for more information on eligable
cryptographic methods and keys that can be used when registering a Client.

# OpenID Provider profile
* TBD: add section on access token? (on top of / in relation to OAuth2)

## ID Tokens
All ID Tokens MUST be signed by the OpenID Provider's private signature key.
ID Tokens MAY be encrypted using the appropriate key of the requesting client.

The ID Token MUST expire and SHOULD have an active lifetime no longer than
five minutes. Since the ID token is consumed by the Client and not presented
to remote systems, much shorter expiration times are RECOMMENDED where
possible.

The token response includes an access token (which can be used to make a
UserInfo request) and ID Token (a signed and optionally encrypted JSON Web
Token). ID Token values have the following meanings:

iss

>    REQUIRED. The "issuer" field is the Uniform Resource Locater (URL) of the expected issuer.

aud

>    REQUIRED. The "audience" field contains the client ID of the client.

sub

>    REQUIRED. The identifier of the user. OpenID Providers MUST support a pairwise identifier in accordance with OpenID Connect Core section 8.1. See Pairwise Identifiers below on when it may be useful to relax this requirement.

sub\_id\_type

>	  REQUIRED. The type of identifier used for the subject. In order to support multiple type of identifiers in an interoperable way,
>     the type of identifier used for the identifier in `sub` is explicitly included. The value of the sub\_id\_type MUST be a URI.

acr

>    REQUIRED. The LoA the user was authenticated at. MUST be a member of the acr_values list from the authentication request. See Authentication Context for more details.

nonce

>    REQUIRED. MUST match the nonce value that was provided in the Authentication Request.

jti

>    REQUIRED. A unique identifier for the token, which can be used to prevent reuse of the token. The value of `jti` MUST uniquely identity the ID Token between sender and receiver for at least 12 months.

auth_time

>    RECOMMENDED. This SHOULD be included if the OpenID Provider can assert an end- user's authentication intent was demonstrated. For example, a login event where the user took some action to authenticate.

exp, iat, nbf

>    REQUIRED. The "expiration", "issued at", and "not before" timestamps for the token are dates (integer number of seconds since from 1970-01-01T00:00:00Z UTC) within acceptable ranges.

represents

>	REQUIRED in case Representation is applicable, the `represents` Claim provides information about the effective authorization for the acting party.

vot

>    OPTIONAL. The vector value as specified in Vectors of Trust. See Vectors of Trust for more details. As eIDAS is leading in many scenarios, using the `acr` Claim to express the Level of Assurance is preferred over Vectors of Trust.

vtm

>    REQUIRED if vot is provided. The trustmark URI as specified in Vectors of Trust. See Vectors of Trust for more details.

Other Claims MAY be included. See Claims Request below on how such Claims SHOULD be requested by the Client to be provided by the OpenID Provider.

Any Relying Party MUST be able to process `represents` Claims. As an exceptions a `represents` Claims MAY be ignored, if and only if the explicitly agreed upon before hand that no Representation will be provided.

This example ID Token has been signed using the server's RSA key:



    eyJhbGciOiJSUzI1NiJ9.eyJhdXRoX3RpbWUiOjE0
            MTg2OTg3ODIsImV4cCI6MTQxODY5OTQxMiwic3ViI
            joiNldaUVBwblF4ViIsIm5vbmNlIjoiMTg4NjM3Yj
            NhZjE0YSIsImF1ZCI6WyJjMWJjODRlNC00N2VlLTR
            iNjQtYmI1Mi01Y2RhNmM4MWY3ODgiXSwiaXNzIjoi
            aHR0cHM6XC9cL2lkcC1wLmV4YW1wbGUuY29tXC8iL
            CJpYXQiOjE0MTg2OTg4MTJ9mQc0rtL56dnJ7_zO_f
            x8-qObsQhXcn-qN-FC3JIDBuNmP8i11LRA_sgh_om
            RRfQAUhZD5qTRPAKbLuCD451lf7ALAUwoGg8zAASI
            5QNGXoBVVn7buxPd2SElbSnHxu0o8ZsUZZwNpircW
            NUlYLje6APJf0kre9ztTj-5J1hRKFbbHodR2I1m5q
            8zQR0ql-FoFlOfPhvfurXxCRGqP1xpvLLBUi0JAw3
            F8hZt_i1RUYWMqLQZV4VU3eVNeIPAD38qD1fxTXGV
            Ed2XDJpmlcxjrWxzJ8fGfJrbsiHCzmCjflhv34O22
            zb0lJpC0d0VScqxXjNTa2-ULyCoehLcezmssg

Its claims are as follows:



     {
            "auth_time": 1418698782,
            "exp": 1418699412,
            "sub": "6WZQPpnQxV",
			"sub_id_type": "urn:nl-eid-gdi:1.0:id:pseudonym",
            "nonce": "188637b3af14a",
            "aud": [
              "c1bc84e4-47ee-4b64-bb52-5cda6c81f788"
            ],
            "iss": "https://idp-p.example.com/",
            "acr": "http://eidas.europa.eu/LoA/substantial",
            "iat": 1418698812,
			"jti": "a65c560d-085c-466e-97c5-f8639fca5ea7",
            "nbf": 1418699112,
      }


## Pairwise Identifiers
Pairwise identifiers specified in OpenID Connect Core section 8 help protect
an end user's privacy by allowing an OpenID Provider to represent a single
user with a different subject identifier (sub) for every Client the user
connects to. This technique can help mitigate correlation of a user between
multiple clients by preventing the clients from using the subject identifier
(the sub claim) to track a user between different sites and applications. Use
of pairwise identifiers does not prevent clients from correlating data based
on other identifying attributes such as names, phone numbers, email addresses,
document numbers, or other attributes. However, since not all transactions
require access to these attributes, but a subject identifier is always
required, a pairwise identifier will aid in protecting the privacy of end
users as they navigate the system.

OpenID Providers MUST support pairwise identifiers for cases where clients
require this functionality. OpenID Providers MAY support public identifiers
for frameworks where public identifiers are required, or for cases where
public identifiers are shared as attributes and the framework does not have a
requirement for subject anonymity.

The _Burgerservicenummer_ (citizen service number, or _BSN_) is often used
in the Netherlands as identifier for citizens or natural persons. The BSN is
considered a public sectoral identifier in this profile.
Note that the BSN MUST only be used by Relying Parties for Service eligible
for using the BSN and the BSN SHOULD be encrypted.

Other public identifiers, such as the 
_Rechtspersonen en Samenwerkingsverbanden Identificatienummer_ (RSIN) or 
_Kamer van Koophandel_ (KvK) number for legal entities,
are similarly considered public sectoral identifiers.

* TBD: include PP-pseudonyms as pairwise?

## UserInfo Endpoint
OpenID Providers MUST support the UserInfo Endpoint and, at a minimum, the sub
(subject) claim. It is expected that the sub claim will remain pseudonymous in
Use Cases where obtaining personal information is not needed.

Support for a UserInfo Endpoint is important for maximum client implementation
interoperability even if no additional user information is returned. Clients
are not required to call the UserInfo Endpoint, but should not receive an
error if they do.

In an example transaction, the client sends a request to the UserInfo Endpoint
like the following:

    GET /userinfo HTTP/1.1
    Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTg3MDI0MTIsIm
      F1ZCI6WyJjMWJjODRlNC00N2VlLTRiNjQtYmI1Mi01Y2RhNmM4MWY3ODgiXSwiaXNzIjo
      iaHR0cHM6XC9cL2lkcC1wLmV4YW1wbGUuY29tXC8iLCJqdGkiOiJkM2Y3YjQ4Zi1iYzgx
      LTQwZWMtYTE0MC05NzRhZjc0YzRkZTMiLCJpYXQiOjE0MTg2OTg4MTJ9i.HMz_tzZ90_b
      0QZS-AXtQtvclZ7M4uDAs1WxCFxpgBfBanolW37X8h1ECrUJexbXMD6rrj_uuWEqPD738
      oWRo0rOnoKJAgbF1GhXPAYnN5pZRygWSD1a6RcmN85SxUig0H0e7drmdmRkPQgbl2wMhu
      -6h2Oqw-ize4dKmykN9UX_2drXrooSxpRZqFVYX8PkCvCCBuFy2O-HPRov_SwtJMk5qjU
      WMyn2I4Nu2s-R20aCA-7T5dunr0iWCkLQnVnaXMfA22RlRiU87nl21zappYb1_EHF9ePy
      q3Q353cDUY7vje8m2kKXYTgc_bUAYuW-W3SMSw5UlKaHtSZ6PQICoA
    Accept: text/plain, application/json, application/*+json, */*
    Host: idp-p.example.com
    Connection: Keep-Alive
    User-Agent: Apache-HttpClient/4.2.3 (java 1.5)

And receives a document in response like the following:

    HTTP/1.1 200 OK
    Date: Tue, 16 Dec 2014 03:00:12 GMT
    Access-Control-Allow-Origin: *
    Content-Type: application/json;charset=ISO-8859-1
    Content-Language: en-US
    Content-Length: 333
    Connection: close

    {
       "sub": "6WZQPpnQxV",
       "iss": "https://idp-p.example.com"
       "given_name": "Stephen",
       "family_name": "Emeritus",
    }


OpenID Providers MUST support the generation of JWT encoded responses from the
UserInfo Endpoint in addition to unsigned JSON objects. Signed responses MUST
be signed by the OpenID Provider's key, and encrypted responses MUST be
encrypted with the authorized client's public key. Please refer to
[Algorithms](#algorithms) for more information on cryptographic algorithms
and keys.

* TBD: drop support for unsigned UserInfo?

## Request Objects
OpenID Providers MUST accept requests containing a request object signed by
the Client's private key. Servers MUST validate the signature on such requests
against the Client's registered public key. OpenID Connect Providers MUST
accept request objects encrypted with the server's public key.

OpenID Providers SHOULD accept request objects by reference using the `request_uri`
parameter.

Both of these methods allow for clients to create a request that is protected
from tampering through the browser, allowing for a higher security mode of
operation for clients and applications that require it. Clients are not
required to use request objects, but OpenID Providers are required to support
requests using them.

* TODO: contrary to OIDC core, use unique requests and no overrides in CGI parameters. That is in line with PAR (still under development).

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
OpenID Connect Discovery standard provides a standard, programatic way for
clients to obtain configuration details for communicating with OpenID
Providers. Discovery is an important part of building scalable federation
ecosystems. Compliant OPs under this profile MUST publish their server
metadata to help minimize configuration errors and support automation for
scale-able deployments.

Exposing a Discovery endpoint does NOT inherently put the OpenID Provider at
risk to attack. Endpoints and parameters specified in the Discovery document
SHOULD be considered public information regardless of the existence of the
Discovery document.

Access to the Discovery document MAY be protected with existing web
authentication methods if required by the Provider. Credentials for the
Discovery document are then managed by the Provider. Support for these
authentication methods is outside the scope of this profile.

Endpoints described in the Discovery document MUST be secured in accordance
with this profile and MAY have additional controls the Provider wishes to
support.

All OpenID Providers are uniquely identified by a URL known as the issuer.
This URL serves as the prefix of a service discovery endpoint as specified in
the OpenID Connect Discovery standard and "OAuth2 Authorization Server
Metadata" [[rfc8414]]. An OpenID Provider SHOULD publish
the same JSON metadata on both `/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server`, and MAY publish on other locations.
The OpenID Provider SHOULD include a `signed_metadata` claim, as described in [[rfc8414]]
section 2.1.

Note that for privacy considerations, only direct requests to the server metadata
document SHOULD be used. The webfinger method to locate the relevant OpenID Provider and
its metadata, as described in OpenID Discovery section 2, MUST NOT be used.


The discovery document MUST contain at minimum the following fields:

issuer

>    REQUIRED. The fully qualified issuer URL of the OpenID Provider.

authorization_endpoint

>    REQUIRED. The fully qualified URL of the OpenID Provider's authorization endpoint defined by [[rfc6749]].

token_endpoint

>    REQUIRED. The fully qualified URL of the server's token endpoint defined by [[rfc6749]].

introspection_endpoint

>    OPTIONAL. The fully qualified URL of the server's introspection endpoint defined by OAuth Token Introspection.

revocation_endpoint

>    OPTIONAL. The fully qualified URL of the server's revocation endpoint defined by OAuth Token Revocation.

jwks_uri

>    REQUIRED. The fully qualified URI of the server's public key in JWK Set format. For verifying the signatures on the id_token.

scopes_supported

>    REQUIRED. The list of scopes, including iGov scopes, the server supports.

claims_supported

>    REQUIRED. The list of claims available in the supported scopes. See below.

vot

>    OPTIONAL. The vectors supported.

acr_values

>    OPTIONAL. The acrs supported. See Level of Assurance.

The following example shows the JSON document found at a discovery endpoint
for an authorization server:



    {
      "request_parameter_supported": true,
      "id_token_encryption_alg_values_supported": [
        "RSA-OAEP", "RSA-OAEP-256"
      ],
      "registration_endpoint": "https://idp-p.example.com/register",
      "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512"
      ],
      "token_endpoint": "https://idp-p.example.com/token",
      "request_uri_parameter_supported": false,
      "request_object_encryption_enc_values_supported": [
        "A192CBC-HS384", "A192GCM", "A256CBC+HS512",
        "A128CBC+HS256", "A256CBC-HS512",
        "A128CBC-HS256", "A128GCM", "A256GCM"
      ],
      "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
      ],
      "userinfo_encryption_alg_values_supported": [
        "RSA-OAEP", "RSA-OAEP-256"
      ],
      "subject_types_supported": [
        "public", "pairwise"
      ],
      "id_token_encryption_enc_values_supported": [
        "A192CBC-HS384", "A192GCM", "A256CBC+HS512",
        "A128CBC+HS256", "A256CBC-HS512", "A128CBC-HS256",
        "A128GCM", "A256GCM"
      ],
      "claims_parameter_supported": false,
      "jwks_uri": "https://idp-p.example.com/jwk",
      "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512"
      ],
      "authorization_endpoint": "https://idp-p.example.com/authorize",
      "require_request_uri_registration": false,
      "introspection_endpoint": "https://idp-p.example.com/introspect",
      "request_object_encryption_alg_values_supported": [
        "RSA-OAEP", "RSA-OAEP-256"
      ],
      "service_documentation": "https://idp-p.example.com/about",
      "response_types_supported": [
        "code", "token"
      ],
      "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512"
      ],
      "revocation_endpoint": "https://idp-p.example.com/revoke",
      "request_object_signing_alg_values_supported": [
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
      ],
      "claim_types_supported": [
        "normal"
      ],
      "grant_types_supported": [
        "authorization_code",
      ],
      "scopes_supported": [
        "profile", "openid", "doc"
      ],
      "userinfo_endpoint": "https://idp-p.example.com/userinfo",
      "userinfo_encryption_enc_values_supported": [
        "A192CBC-HS384", "A192GCM", "A256CBC+HS512","A128CBC+HS256",
        "A256CBC-HS512", "A128CBC-HS256", "A128GCM", "A256GCM"
      ],
      "op_tos_uri": "https://idp-p.example.com/about",
      "issuer": "https://idp-p.example.com/",
      "op_policy_uri": "https://idp-p.example.com/about",
      "claims_supported": [
        "sub", "name", "vot", "acr"
      ],
      "acr" " ??? "
    }


It is RECOMMENDED that servers provide cache information through HTTP headers
and make the cache valid for at least one week.
An OpenID Provider SHOULD document its change procedure. In order to support automated
transitions to configuraion updates, an OpenID Provider SHOULD only make non-breaking changes
and retain backward compatability when possible. It is RECOMMENDED an OP
monitors usage of outdated configuration options used by any Relying Party and
actively work with their administrators to update configurations.
The above on caching an changed MUST be applied for the `jwks_uri` containing the
OpenID Provider's key set.

The server MUST provide its public key in JWK Set format, such as the
following 2048-bit RSA key:



    {
      "keys": [
        {
          "alg": "RS256",
          "e": "AQAB",
          "n": "o80vbR0ZfMhjZWfqwPUGNkcIeUcweFyzB2S2T-hje83IOVct8gVg9Fx
                vHPK1ReEW3-p7-A8GNcLAuFP_8jPhiL6LyJC3F10aV9KPQFF-w6Eq6V
                tpEgYSfzvFegNiPtpMWd7C43EDwjQ-GrXMVCLrBYxZC-P1ShyxVBOze
                R_5MTC0JGiDTecr_2YT6o_3aE2SIJu4iNPgGh9MnyxdBo0Uf0TmrqEI
                abquXA1-V8iUihwfI8qjf3EujkYi7gXXelIo4_gipQYNjr4DBNl
                E0__RI0kDU-27mb6esswnP2WgHZQPsk779fTcNDBIcYgyLujlcUATEq
                fCaPDNp00J6AbY6w",
          "kty": "RSA",
          "kid": "rsa1"
        }
      ]
    }

Please refer to [Algorithms](#algorithms) for more information on eligable
cryptographic methods and keys that can be used by OpenID Providers.


## Dynamic Registration
If the OpenID Provider is acting as an NL-iGov OAuth Authorization Server (NL-iGov OAuth2
profile), then Dynamic Registration MUST be supported in accordance with that
specification (see section 3.1.3).

Dynamic Registration MUST also be supported in combination with per-instance provisioning 
of secrets when registering Native Applications as confidential clients.

In other cases, particularly when dealing with Browser-based applications or
Native Apps, Dynamic Registration SHOULD be supported in accordance with the
NL-iGov OAuth2 specification.

# User Info
The availability, quality, and reliability of an individual's identity
attributes will vary greatly across jurisdictions and Provider systems. The
following recommendations ensure maximum cross-jurisdictional
interoperability, while setting Client expectations on the type of data they
may acquire.

## Claim Interoperability
As per section 5.1.2 of the OpenID Core specification, claim names SHOULD be
collision-resistant. It is RECOMMENDED to use domain name based URIs as
attribute names.

OpenID Core section 5.1 specifies a list of standard claims. In a Dutch
governmental context, attribute Claims are commonly registred in the BRP
(_Basis Registratie Personen_, the Dutch citizen registry), as defined in
[[LO.GBA]].
Usage or interoperability with the ISA<sup>2</sup> core vocabularies is
RECOMMENDED.

* TBD: add default/recommended mapping OIDC <-> BRP?
** usable: name, given_name (probably), family_name (possibly), gender, email, phone, locale
** unusable: middle_name (ambiguous), birthdate (unknown day not in OIDC), address (insufficient detail split out, no address type)
** inapplicable: nickname, profile, preferred_username, website, zoneinfo

## Claims Supported
Discovery mandates the inclusion of the `claims_supported` field that defines
the claims a Client MAY expect to receive for the supported scopes. OpenID
Providers MUST return claims on a best effort basis. However, a Provider
asserting it can provide a user claim does not imply that this data is
available for all its users: clients MUST be prepared to receive partial data.
Providers MAY return claims outside of the `claims_supported` list, but they
MUST still ensure that the extra claims to not violate the privacy policies
set out by the trust framework the Provider supports. The Provider MUST ensure
to comply with applicable privacy legislation (e.g. informed consent as per
GDPR) at all times.

* TODO: applicable (recursively) when dealing with representation (act / may\_act\_on\_behalf alike) as well

## Scope Profiles
In the interests of data minimization balanced with the requirement to
successfully identify the individual signing in to a service, the default
OpenID Connect profiles may not be appropriate.

Matching of the identity assertion based on claims to a local identifier or
'account' related to the individual identity at a level of assurance is a
requirement where the government in question is not able to provide a single
identifier for all citizens based on an authoritative register of citizens.

The requirement for matching is also of importance where a cross-border or
cross-jurisdiction authentication is required and therefore the availability
of a single identifier (e.g. social security number) cannot be guaranteed for
the individual wishing to authenticate.

However, in the Netherlands a common identifier (BSN) for citizines is
available for eligable organizations. Nationwide interoperable pseudonyms
per Relying Party for non-eligable organizations is supported as well.

The default 'profile' scope of OIDC is very wide, which is undesired from a
privacy perspective. As such, the profile scope SHOULD NOT be used.

Note that the 'doc' profile described in the iGov profile for OpenID Connect
is not in common use in the Netherlands and therefor not included in this
profile.

## Claims Request
OpenID Core section 5.5 defines a method for a client to request specific
claims in the UserInfo object. OpenID Providers MUST support this claims
parameter in the interest of data minimization - that is, the Provider only
returns information on the subject the Client specifically asks for, and does
not volunteer additonal information about the subject.

Clients requesting the profile scope MAY provide a claims request parameter.
If the claims request is omitted, the OpenID Provider SHOULD provide a default
claims set that it has available for the subject, in accordance with any
policies set out by the trust framework the Provider supports.

* TBD: claims parameter has benefits functionally/security wise, support may be less widespread though

## Claims Response
Response to a UserInfo request MUST match the scope and claims requested to
avoid having a OpenID Provider over-expose a user's identity information.

Claims response MAY also make use of the aggregated and/or distributed claims
structure to refer to the original source of the subject's claims.

## Claims Metadata
Claims Metadata (such as locale or the confidence level the OpenID Provider
has in the Claim for the user) can be expressed as attributes within the
UserInfo object, but are outside the scope of this document. These types of
claims are best described by the trust framework the clients and OpenID
Providers operate within.
It is up to the Relying Party to assess the level of confidence provided by
the OpenID Provider or the trust framework, per claim. Expressing or evaluating such
confidence is beyond the scope of this profile.

In order to provide a source, including integrity and optionally confidentiality,
an OpenID Provider SHOULD be able to provide aggregated or distributed claims. The signee of
such aggregated or distributed claims implies the source and can support in
assessing the level confidence or quality of the claim.


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

Data minimization is an essential concept in trust frameworks and federations
exchanging user identity information for government applications. The design
of this profile takes into consideration mechanisms to protect the
user's government identity information and activity from unintentional
exposure.

Pairwise anonymous identifiers MUST be supported by the OpenID Providers for
frameworks where subjects should not be traceable across clients by their
subject ID. This prevents a situation where a user may inadvertently be
assigned a universal government identifier.

Request claims MUST be supported by the OpenID Providers to ensure that only
the data the client explicitly requests is provided in the UserInfo response
or ID Token.
This prevents situations where a client may only require a partial set of
claims, but receives (and is therefore exposed to) a full set of claims. For
example, if a client only needs an identifier and the persons legal age,
the OpenID Provider MUST NOT send the client the full user name and birthdate.

All Relying Parties MUST apply the concept of data minimization. As a result,
a client MUST NOT request any more identifiers, attributes or other claims
than strictly necessary.
Additionally, clients SHOULD ensure they minimize the scope and audience they
request, use and forward. This principle applies to both to usage at the
client as well as forwarded access tokens in a Service Intermediation scenario.
Token Exchange ([[rfc8693]]) SHOULD be used to request access tokens with a
minimal scope and audience.

Despite the mechanisms enforced by this specification, the operational
circumstances may allow these controls to be relaxed in a specific context.
For example, if a bilateral agreement between to agencies legally entitles 
usage of citizen identifiers, then the pairwise anonymous identifer requirement
may be relaxed. In cases where all clients are entitled to process 
associated to a subject at an OpenID Provider, the claims request requirement
may be relaxed.

The reasons for relaxing the controls that support data minimalization are
outside the scope of this specification.

In order to provide end-to-end security and privacy, identifiers and
attributes SHOULD be encrypted from the providing source to the ultimate
intended recipient. This can be accomplished by either encrypting entire
response and tokens or by utilizing aggregated or distributed claims. applying
end-to-end encryption is strongly RECOMMENDED for both the BSN (_Burger Service
Number_, the Dutch citizen ID) and sensative attributes.

** TODO: check consistency wrt aggregated/distributed claims

# Security considerations
All transactions MUST be protected in transit by TLS as described in BCP195
[[rfc7525]]. In addition, all compliant implementations MUST apply the IT
Security Guidelines for TLS by the Dutch NCSC [[SG.TLS]]. Implementations SHOULD
only implement settings and options indicated as 'good', SHOULD NOT use any
settings with a status 'phase out' and MUST NOT use any setting with a status
'insufficient' in these security guidelines or future updates thereof.

Implementations MUST implement HTTP Strict Transport Security, as specified in
[[rfc6797]].

All clients MUST conform to applicable recommendations found in the Security
Considerations sections of [[rfc6749]] and those found in the OAuth 2.0 Threat
Model and Security Considerations document [[rfc6819]]. For all Tokens, the
JSON Web Token Best Current Practices [[rfc8725]] SHOULD be applied.

<!-- [Algorithms](#algorithms) --->
## Algorithms
Security of OpenID Connect and OAuth2 is significantly based on application of
cryptography. Herein the choice of algorithms is important for both security as
well as interoperability. This section lists relevant choices for algorithms
for all message and tokens.

For signing of messages and tokens, implementations:
- MUST support RS256.
- SHOULD support PS256; usage of PS256 is RECOMMENDED over RS256.
- MAY support other algorithms, provided they are at least equally secure as RS256.
- MUST NOT support algorithms that are less secure than RS256.

For assymetric encryption, in particular encryption of content encryption keys,
implementations:
- MUST support RSA-OAEP.
- SHOULD support RSA-OAEP-256.
- MAY support other algorithms, provided they are at least equally secure as RSA-OAEP.
- MUST NOT support algorithms that are less secure than RSA-OAEP.

For symmetric encryption, implementations:
- MUST support A256GCM.
- MAY support other algorithms, provided they are at least equally secure as A256GCM.
- MUST NOT support algorithms that are less secure than A256GCM.

In addition to proper selection and configuration of algorithms, implementation
MUST ensure to use a cryptographically secure (pseudo)random generator.
Administrators and implementations MUST apply industry best practices for key
management of cryptographic keys. This includes best practices for selection of
applicable key length, as applicable for the relevant algorithms selected.

## Browser-based Applications
In Use Cases that involve Browser-based applications, OpenID Providers and applications 
MUST follow the best practices as specified in 
[OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps). 

In addition to these best practices, the following security measures apply to Use Cases that involve
Browser-Based applications:

- OpenID Providers SHOULD use short-lived access tokens and id tokens and long-lived refresh 
tokens; refresh tokens MUST rotate on each use.
- OpenID Providers MUST support the necessary 
"Cross-Origin Resource Sharing (CORS)"[[cors]] headers to allow browsers to make requests
to its endpoints and SHOULD NOT use wildcard origins.
- Browser-based applications SHOULD restrict its JavaScript execution to a set of statically
hosted scripts via a "Content Security Policy (CSP)"[[CSP 3]].
- Browser-based applications SHOULD use "Subresource Integrity (SRI)" [[SRI]]
to verify that external dependencies that they include (e.g. via a content
delivery network (CDN)) are not unexpectedly manipulated.

TODO: het gebruik van httpOnly cookies voor tokens is meer voor oAuth, omdat het gaat over 
toegang tot een resource server. Wellicht moeten we daar aangeven dat een AS naast een
access_token in de header OOK een httpOnly cookie zet met een token dat afwijkt van het
access token en dat de RS bij elk request zowel het access token als de httpOnly cookie
valideert voor toegang. Hier valt ook webcrypto API onder.
* utilize webcrypto API
* Cookie security

## Native Applications
In Use Cases that involve Native applications, OpenID Providers and applications 
MUST follow the best practices as specified in 
OAuth 2.0 for Native Apps [[RFC8252]].

In addition to these best practices, the following security measures apply to Use Cases that involve
Native applications:

- OpenID Providers SHOULD use short-lived access tokens and id tokens and long-lived refresh 
tokens; refresh tokens MUST rotate on each use.
- Native applications MUST use an external user-agent or in-app browser tab to make authorization 
requests; embedded user-agents or web-view components MUST NOT be used for this purpose.

# Future updates
This profile was creating using published, finalized specifications and
standards as basis. Some relevant new documents are under development at the
time of writing. As this profile does not use any draft documents as basis,
these cannot be included.
However, we want to attend readers to these developments and for them to take
into account that future updates to this profile may incorporate the resulting
standards and specifications. Furthermore we would like encourage readers to
follow relevant developments.


## Federations
This profile acknowledges that federations are widely in use, in particular among (semi-)governmental and public domain. However, no specific support or requirements for federations are included in this version of this profile.
The OpenID Foundation is currently drafting a specification for explicit support of federations using OpenID Connect. Future updates to this profile are likely to adopt this specification once finalized. See [Federation at the OpenID Foundation](https://openid.net/tag/federation/).

## Other features
An RFC for Access Tokens in JWT format is being drafted in the OAuth2 working group at IETF. Future updates to this profile are likely to seek interoperability with such RFC once finalized. See [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-access-token-jwt/).

An RFC for Secured (signed and/or encrypted) Authorization Requests is being drafted in the OAuth2 working group at IETF.
Similarly, an RFC for pushing Authorization Requests to relieve Clients from hosting `request_uri` based requests is being drafted in the OAuth2 working group at IETF.
Both practices are already part of the OpenID Connect Core specifications.
Future updates to this profile are likely to seek interoperability with these RFCs once finalized.

* rar; work in progress @ IETF (OAuth2 WG)

* OAuth2 Security Best Practices, currently in draft / work in progress @ IETF (OAuth2 WG).

* Browser based apps, work in progress @ IETF (OAuth2 WG)


#  Appendix Notices
* (C) copyright OIDF (!), ... TODO
