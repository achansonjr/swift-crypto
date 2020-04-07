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

internal extension String {

    init?(from string: UnsafeMutablePointer<ASN1_STRING>) {
        // returns an internal pointer to the data of ASN1_STRING. This is an internal pointer and it should ***not***
        // be freed or modified in any way.
        let internalPointer = CCryptoBoringSSL_ASN1_STRING_get0_data(string)
        guard let cString = internalPointer else {
            return nil
        }
        self.init(cString: cString)
    }

}
