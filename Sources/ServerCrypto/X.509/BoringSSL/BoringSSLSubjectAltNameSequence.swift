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

/// A helper sequence object that enables us to represent subject alternative names
/// as an iterable Swift sequence.
final class BoringSSLSubjectAltNameSequence: Sequence, IteratorProtocol {
    public typealias Element = Certificate.AlternativeName

    private let nameStack: OpaquePointer
    private var nextIdx: Int
    private let stackSize: Int

    init(nameStack: OpaquePointer) {
        self.nameStack = nameStack
        self.stackSize = CCryptoBoringSSL_sk_GENERAL_NAME_num(nameStack)
        self.nextIdx = 0
    }

    func next() -> Certificate.AlternativeName? {
        guard self.nextIdx < self.stackSize else {
            return nil
        }

        guard let name = CCryptoBoringSSL_sk_GENERAL_NAME_value(self.nameStack, self.nextIdx) else {
            fatalError("Unexpected null pointer when unwrapping SAN value")
        }

        self.nextIdx += 1

        switch name.pointee.type {
        case GEN_DNS:
            guard let nameString = String(from: name.pointee.d.ia5) else {
                // This should throw, but we can't throw from next(). Skip this instead.
                return self.next()
            }
            return .dnsName(nameString)
        case GEN_IPADD:
            let addrPtr = UnsafeBufferPointer(start: CCryptoBoringSSL_ASN1_STRING_get0_data(name.pointee.d.ia5),
                                              count: Int(CCryptoBoringSSL_ASN1_STRING_length(name.pointee.d.ia5)))
            guard let addr = IPAddress(copyingBytesFrom: addrPtr) else {
                // This should throw, but we can't throw from next(). Skip this instead.
                return self.next()
            }
            return .ipAddress(addr)
        default:
            // We don't recognise this name type. Skip it.
            return next()
        }
    }

    deinit {
        CCryptoBoringSSL_GENERAL_NAMES_free(self.nameStack)
    }
}

