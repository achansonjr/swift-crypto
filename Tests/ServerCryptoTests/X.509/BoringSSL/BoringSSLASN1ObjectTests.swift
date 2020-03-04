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
@testable import ServerCrypto
import XCTest

final class BoringSSLASN1ObjectTests: XCTestCase {

    func testExistingASN1Object() {
        // NID: 13 is a specific NID called out in the documentation for OpenSSL
        let object = BoringSSLASN1Object(numericalIdentifier: 13)
        XCTAssertEqual(object.objectIdentifier, "2.5.4.3")
        XCTAssertEqual(object.shortName, "CN")
        XCTAssertEqual(object.longName, "commonName")
    }

}
