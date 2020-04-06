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

//"name sequence" (X.501 Name)
//
//"key = values" (AttributeTypeAndValue)
//
//"key is a ASN.1 Object"
//
//"value is a ASN.1 String"

struct BoringSSLX501Name: IteratorProtocol, Sequence {

    let ref: UnsafeMutablePointer<X509_NAME>

    typealias Index = CInt
    typealias Element = (BoringSSLASN1Object?, String?)

    var index: Index = 0

    internal init(ref name: UnsafeMutablePointer<X509_NAME>) {
        ref = name
    }

    var count: Index {
        CCryptoBoringSSL_X509_NAME_entry_count(ref)
    }

    mutating func next() -> BoringSSLX501Name.Element? {
        guard index < count else {
            return nil
        }
        defer {
            index = index + 1
        }
        return CCryptoBoringSSL_X509_NAME_get_entry(ref, index).map { (ptr: UnsafeMutablePointer<X509_NAME_ENTRY>) -> (BoringSSLASN1Object?, String?) in
            let object = CCryptoBoringSSL_X509_NAME_ENTRY_get_object(ptr)
                .flatMap { BoringSSLASN1Object(from: $0) }
            let string = CCryptoBoringSSL_X509_NAME_ENTRY_get_data(ptr)
                .flatMap { String(from: $0) }
            return (object, string)
        }
    }

}
