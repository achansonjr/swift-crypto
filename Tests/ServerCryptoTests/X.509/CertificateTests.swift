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

import Foundation
@testable import ServerCrypto
import XCTest

class CertificateTests: XCTestCase {
    func testLoadingGibberishFromMemoryAsPemFails() {
        let keyBytes: [UInt8] = [1, 2, 3]
        XCTAssertNil(Certificate(pem: keyBytes))
    }

    func testLoadingGibberishFromMemoryAsDerFails() {
        let keyBytes: [UInt8] = [1, 2, 3]
        XCTAssertNil(Certificate(der: keyBytes))
    }

    func testEnumeratingSanFields() throws {
        let v4addr = IPAddress(from: "192.168.0.1")!
        let v6addr = IPAddress(from: "2001:db8::1")!

        let expectedSanFields: [Certificate.AlternativeName] = [
            .dnsName("localhost"),
            .dnsName("example.com"),
            .ipAddress(v4addr),
            .ipAddress(v6addr),
        ]
        let cert = Certificate(pem: multiSanCert)
        XCTAssertNotNil(cert)
        let sans = Array(cert!.subjectAlternativeNames)

        XCTAssertEqual(sans.count, expectedSanFields.count)
        for index in 0..<sans.count {
            XCTAssertEqual(sans[index], expectedSanFields[index])
        }
    }

    func testNonexistentSan() {
        let cert = Certificate(pem: samplePemCert)
        XCTAssertNotNil(cert)
        XCTAssertTrue(Array(cert!.subjectAlternativeNames).isEmpty)
    }

    func testCommonName() {
        let cert = Certificate(pem: samplePemCert)
        XCTAssertEqual("robots.sanfransokyo.edu", cert?.commonName)
    }

    func testMultipleCommonNames() {
        let cert = Certificate(pem: multiCNCert)
        XCTAssertEqual("localhost", cert?.commonName)
    }

    func testNoCommonName() {
        let cert = Certificate(pem: noCNCert)
        XCTAssertNil(cert?.commonName)
    }

    func testUnicodeCommonName() {
        let cert = Certificate(pem: unicodeCNCert)
        XCTAssertEqual("straße.org", cert?.commonName)
    }

    func testSerialNumber() {
        let cert = Certificate(pem: samplePemCert)
        XCTAssertEqual(cert?.serialNumber, "9fd7d05a34ca7984")
    }

    func testSignatureAlgorithm() {
        let cert = Certificate(pem: samplePemCert)
        XCTAssertEqual(cert?.signatureAlgorithm?.longName, "sha256WithRSAEncryption")
    }

    func testNotBefore() {
        let cert = Certificate(pem: samplePemCert)
        XCTAssertEqual(cert?.notBefore?.description(with: nil), "2017-10-16 21:01:02 +0000")
    }

    func testNotAfter() {
        let cert = Certificate(pem: samplePemCert)
        XCTAssertEqual(cert?.notAfter?.description(with: nil), "2047-10-09 21:01:02 +0000")
    }

}
