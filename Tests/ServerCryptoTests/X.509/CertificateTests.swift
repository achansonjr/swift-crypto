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

import Crypto
import Foundation
import ServerCrypto
import XCTest

class CertificateTests: XCTestCase {
    static var pemCertFilePath: String! = nil
    static var pemCertsFilePath: String! = nil
    static var derCertFilePath: String! = nil

    override class func setUp() {
        CertificateTests.pemCertFilePath = try! dumpToFile(text: samplePemCert)
        CertificateTests.pemCertsFilePath = try! dumpToFile(text: samplePemCerts)
        CertificateTests.derCertFilePath = try! dumpToFile(data: sampleDerCert)
    }

    override class func tearDown() {
        _ = CertificateTests.pemCertFilePath.withCString {
            unlink($0)
        }
        _ = CertificateTests.pemCertsFilePath.withCString {
            unlink($0)
        }
        _ = CertificateTests.derCertFilePath.withCString {
            unlink($0)
        }
    }


    func testLoadingGibberishFromMemoryAsPemFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        do {
            _ = try Certificate(pem: keyBytes)
            XCTFail("Gibberish successfully loaded")
        } catch CryptoKitError.underlyingCoreCryptoError(error: _) {
            // Do nothing.
        }
    }

    func testLoadingGibberishFromMemoryAsDerFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        do {
            _ = try Certificate(der: keyBytes)
            XCTFail("Gibberish successfully loaded")
        } catch CryptoKitError.underlyingCoreCryptoError(error: _) {
            // Do nothing.
        }
    }



    func testEnumeratingSanFields() throws {
        var v4addr = in_addr()
        var v6addr = in6_addr()
        precondition(inet_pton(AF_INET, "192.168.0.1", &v4addr) == 1)
        precondition(inet_pton(AF_INET6, "2001:db8::1", &v6addr) == 1)

        let expectedSanFields: [Certificate.AlternativeName] = [
            .dnsName(Array("localhost".utf8)),
            .dnsName(Array("example.com".utf8)),
            .ipAddress(.ipv4(v4addr)),
            .ipAddress(.ipv6(v6addr)),
        ]
        let cert = try Certificate(pem: multiSanCert)
        let sans = [Certificate.AlternativeName](cert.subjectAlternativeNames()!)

        XCTAssertEqual(sans.count, expectedSanFields.count)
        for index in 0..<sans.count {
            switch (sans[index], expectedSanFields[index]) {
            case (.dnsName(let actualName), .dnsName(let expectedName)):
                XCTAssertEqual(actualName, expectedName)
            case (.ipAddress(.ipv4(var actualAddr)), .ipAddress(.ipv4(var expectedAddr))):
                XCTAssertEqual(memcmp(&actualAddr, &expectedAddr, MemoryLayout<in_addr>.size), 0)
            case (.ipAddress(.ipv6(var actualAddr)), .ipAddress(.ipv6(var expectedAddr))):
                XCTAssertEqual(memcmp(&actualAddr, &expectedAddr, MemoryLayout<in6_addr>.size), 0)
            default:
                XCTFail("Invalid entry in sans.")
            }
        }
    }

    func testNonexistentSan() throws {
        let cert = try Certificate(pem: samplePemCert)
        XCTAssertNil(cert.subjectAlternativeNames())
    }

    func testCommonName() throws {
        let cert = try Certificate(pem: samplePemCert)
        XCTAssertEqual([UInt8]("robots.sanfransokyo.edu".utf8), cert.commonName()!)
    }

    func testMultipleCommonNames() throws {
        let cert = try Certificate(pem: multiCNCert)
        XCTAssertEqual([UInt8]("localhost".utf8), cert.commonName()!)
    }

    func testNoCommonName() throws {
        let cert = try Certificate(pem: noCNCert)
        XCTAssertNil(cert.commonName())
    }

    func testUnicodeCommonName() throws {
        let cert = try Certificate(pem: unicodeCNCert)
        XCTAssertEqual([UInt8]("straße.org".utf8), cert.commonName()!)
    }

    func testExtractingPublicKey() throws {
        let cert = try assertNoThrowWithValue(Certificate(pem: samplePemCert))
        let publicKey = try assertNoThrowWithValue(cert.extractPublicKey())
        let spkiBytes = try assertNoThrowWithValue(publicKey.toSPKIBytes())

        XCTAssertEqual(spkiBytes, sampleDerCertSPKI)
    }

    func testDumpingPEMCert() throws {
        let expectedCertBytes = [UInt8](sampleDerCert)
        let cert = try assertNoThrowWithValue(Certificate(pem: samplePemCert))
        let certBytes = try assertNoThrowWithValue(cert.toDERBytes())

        XCTAssertEqual(certBytes, expectedCertBytes)
    }

    func testDumpingDERCert() throws {
        let expectedCertBytes = [UInt8](sampleDerCert)
        let cert = try assertNoThrowWithValue(Certificate(der: expectedCertBytes))
        let certBytes = try assertNoThrowWithValue(cert.toDERBytes())

        XCTAssertEqual(certBytes, expectedCertBytes)
    }
}
