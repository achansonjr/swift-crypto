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
import Crypto
import Foundation

/// A container for RFC 5280 defined public key certificates known as X.509 Public Key Infrastructure Certificate.
///
/// Public key certificates, also known as digital certificates or identity certificates, are used to prove the
/// ownership of a public key.
///
/// The certificate contains information about the key and information about the owner of the key. Additionally, the
/// certificate contains a digital signature of another entity that has verified the certificate. These facts can be
/// used to create a trust chain.
public struct Certificate {

    private let box: X509Certificate

    public enum AlternativeName {
        case dnsName([UInt8])
        case ipAddress(IPAddress)
    }

    public enum IPAddress {
        case ipv4(in_addr)
        case ipv6(in6_addr)
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
    public init(pem string: String) throws {
//        var copy = string
//        precondition(copy.isContiguousUTF8)
//        box = try copy.withUTF8 { try X509Certificate(pem: $0) }
        let data = Data(string.utf8)
        box = try X509Certificate(pem: data)
    }

    /// Create a new `Certificate` from a buffer of bytes that contains the textual encoding format known as
    /// Privacy-Enhanced Mail (PEM) as defined in RFC 7468.
    ///
    /// - Parameter bytes: A buffer of bytes containg PEM encoded X.509 data.
    public init<B: ContiguousBytes>(pem bytes: B) throws {
        box = try X509Certificate(pem: bytes)
    }

    /// Create a new `Certificate` from a buffer of bytes in Distinguished Encoding Rules (DER) format.
    ///
    /// - Parameter bytes: A buffer of bytes containg DER encoded X.509 data.
    public init<B: ContiguousBytes>(der bytes: B) throws {
        box = try X509Certificate(der: bytes)
    }

}

// MARK:- Accessing X.509 Properties

extension Certificate {

    /// Get a sequence of the alternative names in the certificate.
    public func subjectAlternativeNames() -> SubjectAltNameSequence? {
        guard let sanExtension = CCryptoBoringSSL_X509_get_ext_d2i(box.ref, NID_subject_alt_name, nil, nil) else {
            return nil
        }
        return SubjectAltNameSequence(nameStack: OpaquePointer(sanExtension))
    }

    /// Returns the commonName field in the Subject of this certificate.
    ///
    /// It is technically possible to have multiple common names in a certificate. As the primary
    /// purpose of this field in SwiftCrypto is to validate TLS certificates, we only ever return
    /// the *most significant* (i.e. last) instance of commonName in the subject.
    public func commonName() -> [UInt8]? {
        // No subject name is unexpected, but it gives us an easy time of handling this at least.
        guard let subjectName = CCryptoBoringSSL_X509_get_subject_name(box.ref) else {
            return nil
        }

        // Per the man page, to find the first entry we set lastIndex to -1. When there are no
        // more entries, -1 is returned as the index of the next entry.
        var lastIndex: CInt = -1
        var nextIndex: CInt = -1
        repeat {
            lastIndex = nextIndex
            nextIndex = CCryptoBoringSSL_X509_NAME_get_index_by_NID(subjectName, NID_commonName, lastIndex)
        } while nextIndex >= 0

        // It's totally allowed to have no commonName.
        guard lastIndex >= 0 else {
            return nil
        }

        // This is very unlikely, but it could happen.
        guard let nameData = CCryptoBoringSSL_X509_NAME_ENTRY_get_data(CCryptoBoringSSL_X509_NAME_get_entry(subjectName, lastIndex)) else {
            return nil
        }

        // Cool, we have the name. Let's have BoringSSL give it to us in UTF-8 form and then put those bytes
        // into our own array.
        var encodedName: UnsafeMutablePointer<UInt8>? = nil
        let stringLength = CCryptoBoringSSL_ASN1_STRING_to_UTF8(&encodedName, nameData)

        guard let namePtr = encodedName else {
            return nil
        }

        let arr = [UInt8](UnsafeBufferPointer(start: namePtr, count: Int(stringLength)))
        CCryptoBoringSSL_OPENSSL_free(namePtr)
        return arr
    }

}

// MARK:- Utility Functions
// We don't really want to get too far down the road of providing helpers for things like certificates
// and private keys: this is really the domain of alternative cryptography libraries. However, to
// enable users of swift-crypto to use other cryptography libraries it will be helpful to provide
// the ability to obtain the bytes that correspond to certificates and keys.
extension Certificate {
    /// Obtain the public key for this `Certificate`.
    ///
    /// - returns: This certificate's `PublicKey`.
    /// - throws: If an error is encountered extracting the key.
    public func extractPublicKey() throws -> PublicKey {
        guard let key = CCryptoBoringSSL_X509_get_pubkey(box.ref) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return PublicKey.fromInternalPointer(takingOwnership: key)
    }

    /// Extracts the bytes of this certificate in DER format.
    ///
    /// - returns: The DER-encoded bytes for this certificate.
    /// - throws: If an error occurred while serializing the certificate.
    public func toDERBytes() throws -> [UInt8] {
        return try self.withUnsafeDERCertificateBuffer { Array($0) }
    }


    /// Calls the given body function with a temporary buffer containing the DER-encoded bytes of this
    /// certificate. This function does allocate for these bytes, but there is no way to avoid doing so with the
    /// X509 API in BoringSSL.
    ///
    /// The pointer provided to the closure is not valid beyond the lifetime of this method call.
    private func withUnsafeDERCertificateBuffer<T>(_ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
        guard let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_mem()) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        let rc = CCryptoBoringSSL_i2d_X509_bio(bio, box.ref)
        guard rc == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CCryptoBoringSSL_BIO_get_mem_data(bio, &dataPtr)

        guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return try body(bytes)
    }
}

extension Certificate: Equatable {
    public static func ==(lhs: Certificate, rhs: Certificate) -> Bool {
        return CCryptoBoringSSL_X509_cmp(lhs.box.ref, rhs.box.ref) == 0
    }
}


extension Certificate: Hashable {
    public func hash(into hasher: inout Hasher) {
        // We just hash the DER bytes of the cert. If we can't get the bytes, this is a fatal error as
        // we have no way to recover from it. It's unfortunate that this allocates, but the code to hash
        // a certificate in any other way is too fragile to justify.
        try! self.withUnsafeDERCertificateBuffer { hasher.combine(bytes: $0) }
    }
}

extension Certificate.IPAddress {
  init?(addressFromBytes bytes: UnsafeBufferPointer<UInt8>) {
    switch bytes.count {
    case 4:
        let addr = bytes.baseAddress?.withMemoryRebound(to: in_addr.self, capacity: 1) {
            return $0.pointee
        }
        guard let innerAddr = addr else {
            return nil
        }
        self = .ipv4(innerAddr)
    case 16:
        let addr = bytes.baseAddress?.withMemoryRebound(to: in6_addr.self, capacity: 1) {
            return $0.pointee
        }
        guard let innerAddr = addr else {
            return nil
        }
        self = .ipv6(innerAddr)
    default:
        return nil
    }
  }
}
