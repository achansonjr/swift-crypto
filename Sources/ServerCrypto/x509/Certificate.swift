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

/// Wraps a single error from BoringSSL.
public struct BoringSSLInternalError: Equatable, CustomStringConvertible {
    let errorCode: UInt32

    var errorMessage: String? {
        // TODO(cory): This should become non-optional in the future, as it always succeeds.
        var scratchBuffer = [CChar](repeating: 0, count: 512)
        return scratchBuffer.withUnsafeMutableBufferPointer { pointer in
            CCryptoBoringSSL_ERR_error_string_n(self.errorCode, pointer.baseAddress!, pointer.count)
            return String(cString: pointer.baseAddress!)
        }
    }

    public var description: String {
        return "Error: \(errorCode) \(errorMessage ?? "")"
    }

    init(errorCode: UInt32) {
        self.errorCode = errorCode
    }

    public static func ==(lhs: BoringSSLInternalError, rhs: BoringSSLInternalError) -> Bool {
        return lhs.errorCode == rhs.errorCode
    }

}

/// A representation of BoringSSL's internal error stack: a list of BoringSSL errors.
public typealias CryptoBoringSSLErrorStack = [BoringSSLInternalError]

/// An enum that wraps individual BoringSSL errors directly.
public enum BoringCertificateError: Error {
    case noError
    case zeroReturn
    case wantRead
    case wantWrite
    case wantConnect
    case wantAccept
    case wantX509Lookup
    case wantCertificateVerify
    case syscallError
    case sslError(CryptoBoringSSLErrorStack)
    case unknownError(CryptoBoringSSLErrorStack)
    case invalidSNIName(CryptoBoringSSLErrorStack)
    case failedToSetALPN(CryptoBoringSSLErrorStack)
}

extension BoringCertificateError: Equatable {}

public func ==(lhs: BoringCertificateError, rhs: BoringCertificateError) -> Bool {
    switch (lhs, rhs) {
    case (.noError, .noError),
         (.zeroReturn, .zeroReturn),
         (.wantRead, .wantRead),
         (.wantWrite, .wantWrite),
         (.wantConnect, .wantConnect),
         (.wantAccept, .wantAccept),
         (.wantX509Lookup, .wantX509Lookup),
         (.wantCertificateVerify, .wantCertificateVerify),
         (.syscallError, .syscallError):
        return true
    case (.sslError(let e1), .sslError(let e2)),
         (.unknownError(let e1), .unknownError(let e2)),
         (.invalidSNIName(let e1), .invalidSNIName(let e2)),
         (.failedToSetALPN(let e1), .failedToSetALPN(let e2)):
        return e1 == e2
    default:
        return false
    }
}

internal extension BoringCertificateError {
    static func fromSSLGetErrorResult(_ result: CInt) -> BoringCertificateError? {
        switch result {
        case SSL_ERROR_NONE:
            return .noError
        case SSL_ERROR_ZERO_RETURN:
            return .zeroReturn
        case SSL_ERROR_WANT_READ:
            return .wantRead
        case SSL_ERROR_WANT_WRITE:
            return .wantWrite
        case SSL_ERROR_WANT_CONNECT:
            return .wantConnect
        case SSL_ERROR_WANT_ACCEPT:
            return .wantAccept
        case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
            return .wantCertificateVerify
        case SSL_ERROR_WANT_X509_LOOKUP:
            return .wantX509Lookup
        case SSL_ERROR_SYSCALL:
            return .syscallError
        case SSL_ERROR_SSL:
            return .sslError(buildErrorStack())
        default:
            return .unknownError(buildErrorStack())
        }
    }
    
    static func buildErrorStack() -> CryptoBoringSSLErrorStack {
        var errorStack = CryptoBoringSSLErrorStack()
        
        while true {
            let errorCode = CCryptoBoringSSL_ERR_get_error()
            if errorCode == 0 { break }
            errorStack.append(BoringSSLInternalError(errorCode: errorCode))
        }
        
        return errorStack
    }
}

/// Errors that can be raised by Crypto's BoringSSL wrapper.
public enum CryptoCertificateError: Error {
    case writeDuringTLSShutdown
    case unableToAllocateBoringSSLObject
    case noSuchFilesystemObject
    case failedToLoadCertificate
    case failedToLoadPrivateKey
    case handshakeFailed(BoringCertificateError)
    case shutdownFailed(BoringCertificateError)
    case cannotMatchULabel
    case noCertificateToValidate
    case unableToValidateCertificate
    case cannotFindPeerIP
    case readInInvalidTLSState
    case uncleanShutdown
}

extension CryptoCertificateError: Equatable {
    public static func ==(lhs: CryptoCertificateError, rhs: CryptoCertificateError) -> Bool {
        switch (lhs, rhs) {
        case (.writeDuringTLSShutdown, .writeDuringTLSShutdown),
             (.unableToAllocateBoringSSLObject, .unableToAllocateBoringSSLObject),
             (.noSuchFilesystemObject, .noSuchFilesystemObject),
             (.failedToLoadCertificate, .failedToLoadCertificate),
             (.failedToLoadPrivateKey, .failedToLoadPrivateKey),
             (.cannotMatchULabel, .cannotMatchULabel),
             (.noCertificateToValidate, .noCertificateToValidate),
             (.unableToValidateCertificate, .unableToValidateCertificate),
             (.cannotFindPeerIP, .cannotFindPeerIP),
             (.readInInvalidTLSState, .readInInvalidTLSState),
             (.uncleanShutdown, .uncleanShutdown):
            return true
        case (.handshakeFailed(let err1), .handshakeFailed(let err2)),
             (.shutdownFailed(let err1), .shutdownFailed(let err2)):
            return err1 == err2
        default:
            return false
        }
    }
}

public enum CryptoSerializationFormats {
    case pem
    case der
}

private func createX509Ref<C: ContiguousBytes>(bytes: C, format: CryptoSerializationFormats) throws -> UnsafeMutablePointer<X509>? {
  let ref = bytes.withUnsafeBytes { (ptr) -> UnsafeMutablePointer<X509>? in
    let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

    defer {
      CCryptoBoringSSL_BIO_free(bio)
    }

    switch format {
    case .pem:
      return CCryptoBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
    case .der:
      return CCryptoBoringSSL_d2i_X509_bio(bio, nil)
    }
  }

  if ref == nil {
    throw CryptoCertificateError.failedToLoadCertificate
  }

  return ref
}

/// A reference to a BoringSSL Certificate object (`X509 *`).
///
/// This thin wrapper class allows us to use ARC to automatically manage
/// the memory associated with this TLS certificate. That ensures that BoringSSL
/// will not free the underlying buffer until we are done with the certificate.
///
/// This class also provides several convenience constructors that allow users
/// to obtain an in-memory representation of a TLS certificate from a buffer of
/// bytes or from a file path.
public class Certificate {
    internal let _ref: UnsafeMutableRawPointer/*<X509>*/

    internal var ref: UnsafeMutablePointer<X509> {
        return self._ref.assumingMemoryBound(to: X509.self)
    }

    public enum AlternativeName {
        case dnsName([UInt8])
        case ipAddress(IPAddress)
    }

    public enum IPAddress {
        case ipv4(in_addr)
        case ipv6(in6_addr)
    }

    internal init(withOwnedReference ref: UnsafeMutablePointer<X509>) {
        self._ref = UnsafeMutableRawPointer(ref) // erasing the type for @_implementationOnly import CCryptoBoringSSL
    }

    /// Create a Certificate from a file at a given path in either PEM or
    /// DER format.
    ///
    /// Note that this method will only ever load the first certificate from a given file.
    public convenience init(file: String, format: CryptoSerializationFormats) throws {
      let url = URL(fileURLWithPath: file)
      let data = try Data(contentsOf: url)
      let ref = try createX509Ref(bytes: data, format: format)
      self.init(withOwnedReference: ref!)
    }

    /// Create a Certificate from a buffer of bytes in either PEM or
    /// DER format.
    public convenience init<B: ContiguousBytes>(bytes: B, format: CryptoSerializationFormats) throws {
      let ref = try createX509Ref(bytes: bytes, format: format)
        self.init(withOwnedReference: ref!)
    }

    /// Create a Certificate from a buffer of bytes in either PEM or DER format.
    internal convenience init(bytes ptr: UnsafeRawBufferPointer, format: CryptoSerializationFormats) throws {
        // TODO(cory):
        // The body of this method is exactly identical to the initializer above, except for the "withUnsafeBytes" call.
        // ContiguousBytes would have been the lowest effort way to reduce this duplication, but we can't use it without
        // bringing Foundation in. Probably we should use Sequence where Element == UInt8 and the withUnsafeContiguousBytesIfAvailable
        // method, but that's a much more substantial refactor. Let's do it later.
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        let ref: UnsafeMutablePointer<X509>?

        switch format {
        case .pem:
            ref = CCryptoBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        case .der:
            ref = CCryptoBoringSSL_d2i_X509_bio(bio, nil)
        }

        if ref == nil {
            throw CryptoCertificateError.failedToLoadCertificate
        }

        self.init(withOwnedReference: ref!)
    }

    /// Get a sequence of the alternative names in the certificate.
    public func subjectAlternativeNames() -> SubjectAltNameSequence? {
        guard let sanExtension = CCryptoBoringSSL_X509_get_ext_d2i(self.ref, NID_subject_alt_name, nil, nil) else {
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
        guard let subjectName = CCryptoBoringSSL_X509_get_subject_name(self.ref) else {
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

    deinit {
        CCryptoBoringSSL_X509_free(ref)
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
        guard let key = CCryptoBoringSSL_X509_get_pubkey(self.ref) else {
            throw CryptoCertificateError.unableToAllocateBoringSSLObject
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
            throw CryptoCertificateError.unableToAllocateBoringSSLObject
        }

        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        let rc = CCryptoBoringSSL_i2d_X509_bio(bio, self.ref)
        guard rc == 1 else {
            let errorStack = BoringCertificateError.buildErrorStack()
            throw BoringCertificateError.unknownError(errorStack)
        }

        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CCryptoBoringSSL_BIO_get_mem_data(bio, &dataPtr)

        guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
            throw CryptoCertificateError.unableToAllocateBoringSSLObject
        }

        return try body(bytes)
    }
}

extension Certificate: Equatable {
    public static func ==(lhs: Certificate, rhs: Certificate) -> Bool {
        return CCryptoBoringSSL_X509_cmp(lhs.ref, rhs.ref) == 0
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
