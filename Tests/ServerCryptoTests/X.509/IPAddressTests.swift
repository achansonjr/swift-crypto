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

final class IPAddressTests: XCTestCase {

    func testLoadingIPv4FromBytes() {
        let bytes: [UInt8] = [192, 168, 137, 2]
        let ipv4 = bytes.withUnsafeBufferPointer { IPAddress(copyingBytesFrom: $0) }
        XCTAssertEqual(ipv4?.description, "192.168.137.2")
    }

    func testLoadingIPv6FromBytes() {
        let bytes: [UInt8] = [32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52]
        let ipv6 = bytes.withUnsafeBufferPointer { IPAddress(copyingBytesFrom: $0) }
        XCTAssertEqual(ipv6?.description, "2001:db8:85a3::8a2e:370:7334")
    }

    func testIncorrectByteLength() {
        let bytes: [UInt8] = [32, 1, 13, 184, 133, 163, 0, 0, 0, 138, 46, 3, 112, 115, 52]
        let ipv6 = bytes.withUnsafeBufferPointer { IPAddress(copyingBytesFrom: $0) }
        XCTAssertNil(ipv6)
    }

    func testIPv4AddressDescription() {
        let ip = IPAddress(from: "192.168.137.2")
        XCTAssertNotNil(ip)
        XCTAssertEqual(ip?.description, "192.168.137.2")
    }

    func testIPv6AddressDescription() {
        let fixtures = [
            "0:0:0:0:0:0:0:0" : "::",
            "1:0:0:0:0:0:0:8" : "1::8",
            "0:0:0:0:0:FFFF:204.152.189.116" : "::ffff:204.152.189.116",
        ]
        for fixture in fixtures {
            let ip = IPAddress(from: fixture.key)
            XCTAssertNotNil(ip)
            XCTAssertEqual(ip?.description, fixture.value)
        }
    }

    func testAnyIPAddressReflexivity() {
        let lhs = IPAddress(from: "192.168.137.2")
        let rhs = IPAddress(from: "192.168.137.2")
        let two = IPAddress(from: "192.168.137.2")
        let thr = IPAddress(from: "192.168.137.3")
        XCTAssertNotEqual(lhs, thr)
        // Reflexivity
        // lhs == lhs is always true
        XCTAssertEqual(lhs, lhs)
        XCTAssertEqual(rhs, rhs)
        // Symmetry
        // lhs == rhs implies rhs == lhs
        XCTAssertEqual(lhs, rhs)
        XCTAssertEqual(rhs, lhs)
        // Transitivity
        // lhs == rhs and rhs == two implies lhs == two
        XCTAssertEqual(rhs, two)
        XCTAssertEqual(lhs, two)
    }

    func testEqualityIPv4AndIPv6() {
        let lhs = IPAddress(from: "192.168.137.2")
        let rhs = IPAddress(from: "0:0:0:0:0:FFFF:204.152.189.116")
        XCTAssertNotEqual(lhs, rhs)
    }

}

/// MARK: - Helpers for IPAddress Initialization

extension IPAddress {
    init?(from string: String) {
        guard let addr = Address(from: string) else {
            return nil
        }
        self.init(addr)
    }
}

extension IPAddress.Address {
    init?(from string: String) {
        func ipv4() -> in_addr? {
            var mutable = in_addr()
            let result = inet_pton(AF_INET, string, &mutable)
            guard result == 1 else {
                return nil
            }
            return mutable
        }

        func ipv6() -> in6_addr? {
            var mutable = in6_addr()
            let result = inet_pton(AF_INET6, string, &mutable)
            guard result == 1 else {
                return nil
            }
            return mutable
        }

        if let ip4 = ipv4() {
            self = .ipv4(ip4)
        } else if let ip6 = ipv6() {
            self = .ipv6(ip6)
        } else {
            return nil
        }
    }
}

