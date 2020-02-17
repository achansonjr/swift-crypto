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

    func testLoadingPemCertFromFile() throws {
        let cert1 = try Certificate(file: CertificateTests.pemCertFilePath, format: .pem)
        let cert2 = try Certificate(file: CertificateTests.pemCertFilePath, format: .pem)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testLoadingDerCertFromFile() throws {
        let cert1 = try Certificate(file: CertificateTests.derCertFilePath, format: .der)
        let cert2 = try Certificate(file: CertificateTests.derCertFilePath, format: .der)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testDerAndPemAreIdentical() throws {
        let cert1 = try Certificate(file: CertificateTests.pemCertFilePath, format: .pem)
        let cert2 = try Certificate(file: CertificateTests.derCertFilePath, format: .der)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testLoadingPemCertFromMemory() throws {
        let cert1 = try Certificate(bytes: samplePemCert.data(using: .utf8)!, format: .pem)
        let cert2 = try Certificate(bytes: samplePemCert.data(using: .utf8)!, format: .pem)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testLoadingDerCertFromMemory() throws {
        let certBytes = [UInt8](sampleDerCert)
        let cert1 = try Certificate(bytes: certBytes, format: .der)
        let cert2 = try Certificate(bytes: certBytes, format: .der)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testLoadingGibberishFromMemoryAsPemFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        do {
            _ = try Certificate(bytes: keyBytes, format: .pem)
            XCTFail("Gibberish successfully loaded")
        } catch CryptoCertificateError.failedToLoadCertificate {
            // Do nothing.
        }
    }

    func testLoadingGibberishFromMemoryAsDerFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        do {
            _ = try Certificate(bytes: keyBytes, format: .der)
            XCTFail("Gibberish successfully loaded")
        } catch CryptoCertificateError.failedToLoadCertificate {
            // Do nothing.
        }
    }

    func testLoadingGibberishFromFileAsPemFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        do {
            _ = try Certificate(file: tempFile, format: .pem)
            XCTFail("Gibberish successfully loaded")
        } catch CryptoCertificateError.failedToLoadCertificate {
            // Do nothing.
        }
    }

    func testLoadingNonexistentFileAsPem() throws {
        do {
            _ = try Certificate(file: "/nonexistent/path", format: .pem)
            XCTFail("Did not throw")
        } catch CryptoCertificateError.failedToLoadCertificate {
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
        let cert = try Certificate(bytes: multiSanCert.data(using: .utf8)!, format: .pem)
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
        let cert = try Certificate(bytes: samplePemCert.data(using: .utf8)!, format: .pem)
        XCTAssertNil(cert.subjectAlternativeNames())
    }

    func testCommonName() throws {
        let cert = try Certificate(bytes: samplePemCert.data(using: .utf8)!, format: .pem)
        XCTAssertEqual([UInt8]("robots.sanfransokyo.edu".utf8), cert.commonName()!)
    }

    func testMultipleCommonNames() throws {
        let cert = try Certificate(bytes: multiCNCert.data(using: .utf8)!, format: .pem)
        XCTAssertEqual([UInt8]("localhost".utf8), cert.commonName()!)
    }

    func testNoCommonName() throws {
        let cert = try Certificate(bytes: noCNCert.data(using: .utf8)!, format: .pem)
        XCTAssertNil(cert.commonName())
    }

    func testUnicodeCommonName() throws {
        let cert = try Certificate(bytes: unicodeCNCert.data(using: .utf8)!, format: .pem)
        XCTAssertEqual([UInt8]("straße.org".utf8), cert.commonName()!)
    }

    func testExtractingPublicKey() throws {
        let cert = try assertNoThrowWithValue(Certificate(bytes: samplePemCert.data(using: .utf8)!, format: .pem))
        let publicKey = try assertNoThrowWithValue(cert.extractPublicKey())
        let spkiBytes = try assertNoThrowWithValue(publicKey.toSPKIBytes())

        XCTAssertEqual(spkiBytes, sampleDerCertSPKI)
    }

    func testDumpingPEMCert() throws {
        let expectedCertBytes = [UInt8](sampleDerCert)
        let cert = try assertNoThrowWithValue(Certificate(bytes: samplePemCert.data(using: .utf8)!, format: .pem))
        let certBytes = try assertNoThrowWithValue(cert.toDERBytes())

        XCTAssertEqual(certBytes, expectedCertBytes)
    }

    func testDumpingDERCert() throws {
        let expectedCertBytes = [UInt8](sampleDerCert)
        let cert = try assertNoThrowWithValue(Certificate(bytes: expectedCertBytes, format: .der))
        let certBytes = try assertNoThrowWithValue(cert.toDERBytes())

        XCTAssertEqual(certBytes, expectedCertBytes)
    }
}
