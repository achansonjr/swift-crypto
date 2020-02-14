# Feature name

* Proposal: [SC-0001](CertificateProposal.md)
* Authors: [Ryan Lovelett](https://github.com/RLovelett), [Clint Hanson](https://github.com/achansonjr)
* Review Manager: TBD
* Status: **Awaiting implementation**


* Implementation: [achansonjr/swift-crypto/tree/certificate_proposal](https://github.com/achansonjr/swift-crypto/tree/certificate_proposal)

## Introduction

Having a Certificate primitive that wraps the BoringSSL Certificate construct will make it easier to perform cryptographic functions that rely on x509.

## Motivation

In our project we need a cross platform mechanism to easily extract information out of a Certificate for use in naming applications that utilize TLS to secure communications. We originally started to extend Certificate in the [swift-nio-ssl](https://github.com/apple/swift-nio-ssl) project. After some consideration it just felt to us that this primitive was not exclusive to TLS. In our case, while the certificate was going to be utilized for TLS secured communication, we also needed additional information provided by the certificate to uniquely name the component we were creating on the network due to the required networking protocols specification.

While working out the best place to put this, we also came across the request by @0xTim. [New API Proposal: Support for PEM/DER keys](https://github.com/apple/swift-crypto/issues/27). Based upon the way we chose to implement this new primitive, we felt that it would address our use case as well as theirs.

Having a primitive of `Certificate` inside of `swift-crypto` in a curated repository *seems* like a way to increase adoption as well as creating a branching point for adding functionality surrounding x509 operations. Future pull requests would be made to create a standard means of interrogating the `Certificate` for details about the certificate, to eventually creating other associated primitives such as a `CertificateSigningRequest`. In the interim this change exposes the `Certificate` type as a primitive available to consumers, without requiring a fork of `swift-nio-ssl` to enable the extension of the `NIOSSLCertificate` type.

## Proposed solution

[swift-nio-ssl/Certificate.swift](https://github.com/apple/swift-nio-ssl/blob/master/Sources/NIOSSL/SSLCertificate.swift) already exists in swift-nio-ssl. The implementation meets all the requirements for parsing a PEM/DER certificate utilizing BoringSSL.

Our solution was to create a new library called `ServerCrypto`. Knowing that there was no current "Server Namespace", and no existing analog in CryptoKit, we chose this as an attempt to adhere to this direction:

> Secondly, if the API is judged not to meet the criteria for acceptance in general CryptoKit but is sufficiently important to have available for server use-cases, it will be merged into a Server namespace. APIs are not expected to leave this namespace, as it indicates that they are not generally available but can only be accessed when using Swift Crypto.

## Detailed design

We took the implementation of `NIOSSLCertificate` within `swift-nio-ssl` and copied it. In the process of translation we made it have `Foundation` support and attempted to boil its functionality down to only the things that were necessary for a `Certificate` primitive.

## Source compatibility

This change should be no different than current source compatibility with the existing `swift-crypto` project.

## Alternatives considered

We considered forking  `swift-nio-ssl` and maintaining our own private repository where we extended the `NIOSSLCertificate` to implement the features that we needed. Since `swift-nio-ssl` is focused upon networking, and currently has all of the things it needs exported from the `NIOSSLCertificate` structure to accomplish its requirements of performing TLS secure connections, we figured that the liklihood of getting an extension or modification of the `NIOSSLCertificate` primitive approved was slim.



