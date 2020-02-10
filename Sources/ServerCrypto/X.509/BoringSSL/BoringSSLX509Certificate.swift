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

#if compiler(>=5.1) && compiler(<5.3)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
#else
import CCryptoBoringSSL
import CCryptoBoringSSLShims
#endif
import Foundation

/// A reference to a BoringSSL Certificate object (`X509 *`).
///
/// This thin wrapper class allows us to use ARC to automatically manage the memory associated with this TLS
/// certificate. That ensures that BoringSSL will not free the underlying buffer until we are done with the certificate.
///
/// This class also provides several convenience constructors that allow users to obtain an in-memory representation of
/// a TLS certificate from a buffer of bytes or from a file path.
final class BoringSSLX509Certificate {
    internal let _ref: UnsafeMutableRawPointer/*<X509>*/

    internal var ref: UnsafeMutablePointer<X509> {
        return self._ref.assumingMemoryBound(to: X509.self)
    }

    private typealias BIO2X509 = (UnsafeMutablePointer<BIO>) -> UnsafeMutablePointer<X509>?

    private init?<S: Sequence>(bytes: S, bio2X509: BIO2X509) where S.Element == UInt8 {
        let ref = bytes.withContiguousStorageIfAvailable { (ptr) -> UnsafeMutablePointer<X509>? in
            let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

            defer {
                CCryptoBoringSSL_BIO_free(bio)
            }

            return bio2X509(bio)
        }

        guard case let bio?? = ref else {
            return nil
        }

        self._ref = UnsafeMutableRawPointer(bio) // erasing the type for @_implementationOnly import CCryptoBoringSSL
    }

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
    public convenience init?(pem string: String) {
        self.init(pem: string.utf8)
    }

    /// Create a new `Certificate` from a buffer of bytes that contains the textual encoding format known as
    /// Privacy-Enhanced Mail (PEM) as defined in RFC 7468.
    ///
    /// - Parameter bytes: A buffer of bytes containg PEM encoded X.509 data.
    public convenience init?<S: Sequence>(pem bytes: S) where S.Element == UInt8 {
        self.init(bytes: bytes, bio2X509: {
            CCryptoBoringSSL_PEM_read_bio_X509($0, nil, nil, nil)
        })
    }

    /// Create a new `Certificate` from a buffer of bytes in Distinguished Encoding Rules (DER) format.
    ///
    /// - Parameter bytes: A buffer of bytes containg DER encoded X.509 data.
    public convenience init?<S: Sequence>(der bytes: S) where S.Element == UInt8 {
        self.init(bytes: bytes, bio2X509: {
            CCryptoBoringSSL_d2i_X509_bio($0, nil)
        })
    }

    /// Get a sequence of the alternative names in the certificate.
    public var subjectAlternativeNames: AnySequence<Certificate.AlternativeName> {
        guard let sanExtension = CCryptoBoringSSL_X509_get_ext_d2i(self.ref, NID_subject_alt_name, nil, nil) else {
            return AnySequence(EmptyCollection())
        }
        return AnySequence(BoringSSLSubjectAltNameSequence(nameStack: OpaquePointer(sanExtension)))
    }

    /// Extract the X.509 Certificate value as a hex string.
    public var serialNumber: String? {
        return CCryptoBoringSSL_X509_get_serialNumber(ref) // Get the serial number as ASN1_INTEGER
            .flatMap { CCryptoBoringSSL_ASN1_INTEGER_to_BN($0, nil) } // Convert ASN1_INTEGER to BIGNUM
            .flatMap { CCryptoBoringSSL_BN_bn2hex($0) } // Convert BIGNUM to characters
            .flatMap { String(cString: $0) }
    }

    public var signatureAlgorithm: ASN1Object? {
        let nid = CCryptoBoringSSL_X509_get_signature_nid(ref)
        return BoringSSLASN1Object(numericalIdentifier: nid)
    }

    public var notBefore: Date? {
        return CCryptoBoringSSL_X509_get0_notBefore(ref)
            .flatMap { Date(from: $0) }
    }

    public var notAfter: Date? {
        return CCryptoBoringSSL_X509_get0_notAfter(ref)
            .flatMap { Date(from: $0) }
    }

    private func optionalTupleSift<A, B>(tuple: (A?, B?)) -> (A, B)? {
        if let a = tuple.0, let b = tuple.1 {
            return (a, b)
        } else {
            return nil
        }
    }

    public var issuer: [(key: ASN1Object, value: String)]? {
        return CCryptoBoringSSL_X509_get_issuer_name(ref)
            .map { BoringSSLX501Name(ref: $0).compactMap(optionalTupleSift) }
    }

    public var subject: [(key: ASN1Object, value: String)]? {
        return CCryptoBoringSSL_X509_get_subject_name(ref)
            .map { BoringSSLX501Name(ref: $0).compactMap(optionalTupleSift) }
    }

    deinit {
        CCryptoBoringSSL_X509_free(ref)
    }
}
