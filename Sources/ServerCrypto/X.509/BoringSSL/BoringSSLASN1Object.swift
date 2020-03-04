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

/// A reference to a BoringSSL ASN.1 Object (`ASN1_OBJECT *`). It conforms to `ASN1Object` protocol and enables us to
/// work with the underlying data structures and abstract away the BoringSSL implementation.
///
/// Primarily, this thin wrapper class allows us to use automatic reference counting (ARC) to manage the memory
/// associated with these BoringSSL objects. Allowing for more idiomatic Swift implementations around these concepts.
internal struct BoringSSLASN1Object: ASN1Object {

    private let numericalIdentifier: CInt

    // MARK: - Initializers for testing

    init(objectIdentifier: String, shortName: String, longName: String) {
        // OBJ_cleanup() cleans up OpenSSLs internal object table: this should be called before an application exits if
        // any new objects were added using OBJ_create().
        numericalIdentifier = CCryptoBoringSSL_OBJ_create(objectIdentifier, shortName, longName)
    }

    init(numericalIdentifier: CInt) {
        self.numericalIdentifier = numericalIdentifier
    }

    /// MARK: - Internal initilizers

    init(from: UnsafeMutablePointer<ASN1_OBJECT>) {
        numericalIdentifier = CCryptoBoringSSL_OBJ_obj2nid(from)
    }

    // MARK: - ASN1Object Protocol Conformance

    var shortName: String? {
        let object = CCryptoBoringSSL_OBJ_nid2sn(numericalIdentifier)
        return object.map { String(cString: $0) }
    }

    var longName: String? {
        let object = CCryptoBoringSSL_OBJ_nid2ln(numericalIdentifier)
        return object.map { String(cString: $0) }
    }

    var objectIdentifier: String? {
        let object = CCryptoBoringSSL_OBJ_nid2obj(numericalIdentifier).map { UnsafeMutablePointer(mutating: $0) }
        defer {
            CCryptoBoringSSL_ASN1_OBJECT_free(object)
        }
        // https://www.openssl.org/docs/man1.1.0/man3/OBJ_create.html#bugs
        // OBJ_obj2txt() is awkward and messy to use: it doesn't follow the convention of other OpenSSL functions where
        // the buffer can be set to NULL to determine the amount of data that should be written. Instead buf must point
        // to a valid buffer and buf_len should be set to a positive value. A buffer length of 80 should be more than
        // enough to handle any OID encountered in practice.
        let length: Int32 = 80
        var out = UnsafeMutablePointer<Int8>.allocate(capacity: Int(length))
        defer {
            out.deallocate()
        }
        let code = CCryptoBoringSSL_OBJ_obj2txt(out, length, object, 1)
        guard code >= 0 else {
            return nil
        }
        return String(cString: out)
    }

}
