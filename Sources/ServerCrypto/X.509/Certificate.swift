//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation

/// The `Certificate` type aims to implement the RFC 5280 definition of an X.509 certificate. This definition is used as
/// a standard format for public key certificates. These certificates are digital documents that securely associate
/// cryptographic key pairs with identities such as websites, individuals, or organizations.
///
/// - SeeAlso: RFC 5280
public struct Certificate {

    public enum AlternativeName: Equatable {
        case dnsName(String)
        case ipAddress(IPAddress)
    }

    public typealias X500DistinguishedName = [(key: ASN1Object, value: String)]

    private let impl: BoringSSLX509Certificate

    /// Create a new `Certificate` from a `String` that contains X.509 data in the textual encoding format known as
    /// Privacy-Enhanced Mail (PEM) as defined in RFC 7468.
    ///
    /// Initialing from a String containaing PEM encoded X.509 data.
    ///
    /// # Example
    ///
    /// ```
    /// let text = """
    /// -----BEGIN CERTIFICATE-----
    /// ...
    /// -----END CERTIFICATE-----
    /// """
    /// let x509 = try Certificate(pem: text)
    /// ```
    ///
    /// - Parameter string: A `String` containing PEM encoded X.509 data.
    public init?(pem string: String) {
        self.init(pem: string.utf8)
    }

    /// Create a new `Certificate` from a buffer of bytes that contains the textual encoding format known as
    /// Privacy-Enhanced Mail (PEM) as defined in RFC 7468.
    ///
    /// - Parameter bytes: A buffer of bytes containg PEM encoded X.509 data.
    public init?<S: Sequence>(pem bytes: S) where S.Element == UInt8 {
        guard let certificate = BoringSSLX509Certificate(pem: bytes) else {
            return nil
        }
        impl = certificate
    }

    /// Create a new `Certificate` from a buffer of bytes in Distinguished Encoding Rules (DER) format.
    ///
    /// - Parameter bytes: A buffer of bytes containg DER encoded X.509 data.
    public init?<S: Sequence>(der bytes: S) where S.Element == UInt8 {
        guard let certificate = BoringSSLX509Certificate(der: bytes) else {
            return nil
        }
        impl = certificate
    }

    /// The serial number is a unique positive integer assigned by the certificate-authority (CA) to each certificate.
    ///
    /// Given the uniqueness requirements above, serial numbers can be expected to contain long integers. Certificate
    /// users MUST be able to handle serialNumber values up to 20 octets. Conforming CAs MUST NOT use serialNumber
    /// values longer than 20 octets.
    ///
    /// Given the length  of possible serial numbers and Swift not having an integer type for such number the serial
    /// number is provided as a sequence of hex characters.
    ///
    /// - SeeAlso: 4.1.2.2 of RFC 5280
    public var serialNumber: String? {
        impl.serialNumber
    }

    /// Ahe algorithm identifier for the algorithm used by the certificate-authority (CA) to sign the certificate.
    ///
    /// - SeeAlso: 4.1.2.3 of RFC 5280
    public var signatureAlgorithm: ASN1Object? {
        impl.signatureAlgorithm
    }

    /// The issuer name identifies the entity that has signed and issued the certificate. The issuer field must contain
    /// a non-empty X.500 distinguished name (DN).
    ///
    /// - SeeAlso: Section 4.1.2.4 of RFC 5280
    public var issuer: X500DistinguishedName? {
        return impl.issuer
    }

    /// The date on which the certificate validity period begins.
    ///
    /// The certificate validity period is the time interval during which the certificate-authority (CA) warrants that
    /// it will maintain information about the status of the certificate. The validity period is made of two dates: the
    /// date on which the certificate validity begins and the date on which the certificate validity period ends.
    ///
    /// - SeeAlso: Section 4.1.2.5 of RFC 5280
    public var notBefore: Date? {
        impl.notBefore
    }

    /// The date on which the certificate validity period ends.
    ///
    /// The certificate validity period is the time interval during which the certificate-authority (CA) warrants that
    /// it will maintain information about the status of the certificate. The validity period is made of two dates: the
    /// date on which the certificate validity begins and the date on which the certificate validity period ends.
    ///
    /// - SeeAlso: Section 4.1.2.5 of RFC 5280
    public var notAfter: Date? {
        impl.notAfter
    }

    /// The subject field identifies the entity associated with the public key stored in the subject public key field.
    /// The subject name MAY be carried in the subject field and/or the `subjectAlternativeNames` extension.
    ///
    /// - SeeAlso: Section 4.1.2.6 of RFC 5280
    public var subject: X500DistinguishedName? {
        return impl.subject
    }

    /// Returns the commonName field in the `subject` of this certificate.
    ///
    /// It is technically possible to have multiple common names in a certificate. As the primary purpose of this field
    /// in ServerCrypto is to validate TLS certificates, we only ever return the *most significant* (i.e. last) instance
    /// of commonName in the subject.
    ///
    /// ***NOTE***: This property is not part of the RFC 5280 specification.
    public var commonName: String? {
        subject?.lazy
            .last { $0.key.objectIdentifier == "2.5.4.3" }
            .map { $0.value }
    }

    /// A sequence of the subject alternative names in the certificate.
    ///
    /// The subject alternative name extension allows identities to be bound to the subject of the certificate. These
    /// identities may be included in addition to or in place of the identity in the subject field of the certificate.
    /// Defined options include an Internet electronic mail address, a DNS name, an IP address, and a Uniform Resource
    /// Identifier (URI).
    ///
    /// This particular implementation only supports IP address and DNS name.
    ///
    /// - SeeAlso: Section 4.2.1.6 of RFC 5280
    public var subjectAlternativeNames: AnySequence<AlternativeName> {
        impl.subjectAlternativeNames
    }
}
