# X.509 Public Key Infrastructure (PKI) Certificates

* Proposal: [SC-0001](CertificateProposal.md)
* Authors: [Ryan Lovelett](https://github.com/RLovelett), [Clint Hanson](https://github.com/achansonjr)
* Review Manager: TBD
* Status: **Awaiting implementation**


* Implementation: [achansonjr/swift-crypto/tree/certificate_proposal](https://github.com/achansonjr/swift-crypto/tree/certificate_proposal)

## Introduction

Here we propose a new `Certificate` primitive that provides an idiomatic,
extensible Swift implementation of the standard X.509 Public Key Infrastructure
(PKI) Certificates. The implementaion wraps the BoringSSL X.509 certificate
implementation.

X.509 Public Key Infrastructure (PKI) Certificates provide a standard format
used to transmit public key, or asymmetric, certificates on the internet. X.509
certificates are broadly applicable to many domains in the server-side
community and possibly beyond. This is because X.509 certificates are used in
TLS to provide a strong binding between a party's identity and trust. TLS is
used by a number of application layer protocols to provide secure communication
regardless of transport layer.

X.509 certificates are referenced in a number of
standards. For instance, [RFC 5246: The Transport Layer Security (TLS) Protocol v1.2](https://tools.ietf.org/html/rfc5246). With the format of X.509 certificates being defined in [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280).

Currently, X.509 certificates are not handled in Swift Crypto. However, given
how fundamental the format is to cryptography applications it seems a natural
fit for Swift Crypto.

## Motivation

We were asked to implement an application layer communication protocol on top of TLS. In the course of using the application the user must be shown the certificates used to secure the TLS communications. This means we need a cross-platform mechansim to easily extract information out of the X.509 v3 Certificates (i.e., version number, serial number, validity period, subject name, issuer, etc.).

We searched the Swift community for existing implementations that would enable us to do this. Among the implementations we found there was no common consensus on how to interact with X.509 certificates.

After some consideration it just seemed that there should exist a common way of interacting with X.509 certificates and that Swift Crypto seemed like a good way of providing a common library with a public API.

While working out the best place to put this, we also came across the request by @0xTim. [New API Proposal: Support for PEM/DER keys](https://github.com/apple/swift-crypto/issues/27). Depending upon the way this new primitive is implemented, we felt that it could address our use case as well as theirs.

Having a primitive of `Certificate` inside of `swift-crypto` in a community maintained repository seems like a way to increase adoption. Additonally, it seems like a way to create a library and set of best practices for working with X.509 certificates in Swift. Future pull requests could be made to create a standard means of interrogating `Certificate` for details, creating other associated primitives such as a `CertificateSigningRequest`, or possibly common higher level archive file format types like PKCS #12.

## Proposed solution

[swift-nio-ssl/Certificate.swift](https://github.com/apple/swift-nio-ssl/blob/6ee46effd186e955383f422ddd842a43f9fee1f3/Sources/NIOSSL/SSLCertificate.swift) already exists in swift-nio-ssl. The implementation meets all the requirements for parsing a PEM/DER certificate utilizing BoringSSL.

Our solution was to create a new library called `ServerCrypto`. Knowing that there was no current "Server Namespace", and no existing analog in CryptoKit, we chose this as an attempt to adhere to this direction:

> Secondly, if the API is judged not to meet the criteria for acceptance in general CryptoKit but is sufficiently important to have available for server use-cases, it will be merged into a Server namespace. APIs are not expected to leave this namespace, as it indicates that they are not generally available but can only be accessed when using Swift Crypto.

## Detailed design

We took the implementation of `NIOSSLCertificate` within `swift-nio-ssl` and copied it. In the process of translation we made it have `Foundation` support and attempted to boil its functionality down to only the things that were necessary for a `Certificate` primitive.

## Source compatibility

This change should be no different than current source compatibility with the existing `swift-crypto` project.

## Alternatives considered

We considered forking  `swift-nio-ssl` and maintaining our own private repository where we extended the `NIOSSLCertificate` to implement the features that we needed. Since `swift-nio-ssl` is focused upon networking, and currently has all of the things it needs exported from the `NIOSSLCertificate` structure to accomplish its requirements of performing TLS secure connections, we figured that the liklihood of getting an extension or modification of the `NIOSSLCertificate` primitive approved was slim.



