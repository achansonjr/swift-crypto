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

typealias BIO2X509 = (UnsafeMutablePointer<BIO>) -> UnsafeMutablePointer<X509>?

/// A reference to a BoringSSL Certificate object (`X509 *`).
///
/// This thin wrapper class allows us to use ARC to automatically manage the memory associated with this X.509
/// certificate. That ensures that BoringSSL will not free the underlying buffer until we are done with the certificate.
internal class X509Certificate {

    internal let _ref: UnsafeMutableRawPointer/*<X509>*/

    internal var ref: UnsafeMutablePointer<X509> {
        return self._ref.assumingMemoryBound(to: X509.self)
    }

    convenience init<C: ContiguousBytes>(pem bytes: C) throws {
        try self.init(bytes: bytes, bio2X509: {
            CCryptoBoringSSL_PEM_read_bio_X509($0, nil, nil, nil)
        })
    }

    convenience init<C: ContiguousBytes>(der bytes: C) throws {
        try self.init(bytes: bytes, bio2X509: {
            CCryptoBoringSSL_d2i_X509_bio($0, nil)
        })
    }

    private init<C: ContiguousBytes>(bytes: C, bio2X509: BIO2X509) throws {
        let ref = bytes.withUnsafeBytes { (ptr) -> UnsafeMutablePointer<X509>? in
            let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

            defer {
                CCryptoBoringSSL_BIO_free(bio)
            }

            return bio2X509(bio)
        }

        guard let bio = ref else {
            throw CryptoKitError.internalBoringSSLError()
        }

        _ref = UnsafeMutableRawPointer(bio) // erasing the type for @_implementationOnly import CCryptoBoringSSL
    }

    deinit {
        CCryptoBoringSSL_X509_free(ref)
    }

}
