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
import CCryptoBoringSSL
import CCryptoBoringSSLShims
import Foundation
@testable import ServerCrypto
import XCTest

final class BoringSSLX501NameTests: XCTestCase {

    /// C=UK, O=Disorganized Organization, CN=Joe Bloggs
    /// MEYxCzAJBgNVBAYTAlVLMSIwIAYDVQQKDBlEaXNvcmdhbml6ZWQgT3JnYW5pemF0aW9uMRMwEQYDVQQDDApKb2UgQmxvZ2dz
    /// https://lapo.it/asn1js/#MEYxCzAJBgNVBAYTAlVLMSIwIAYDVQQKDBlEaXNvcmdhbml6ZWQgT3JnYW5pemF0aW9uMRMwEQYDVQQDDApKb2UgQmxvZ2dz
    lazy var joeBloggs: UnsafeMutablePointer<X509_NAME> = {
        let name = CCryptoBoringSSL_X509_NAME_new()

        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "C", MBSTRING_UTF8, "UK", -1, -1, 0)
        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8, "Disorganized Organization", -1, -1, 0)
        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, "Joe Bloggs", -1, -1, 0)

        return name!
    }()

    /// UID=jsmith, DC=example, DC=net
    /// MEYxFjAUBgoJkiaJk/IsZAEBDAZqc21pdGgxFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRMwEQYKCZImiZPyLGQBGRYDbmV0
    /// https://lapo.it/asn1js/#MEYxFjAUBgoJkiaJk_IsZAEBDAZqc21pdGgxFzAVBgoJkiaJk_IsZAEZFgdleGFtcGxlMRMwEQYKCZImiZPyLGQBGRYDbmV0
    lazy var jSmith: UnsafeMutablePointer<X509_NAME> = {
        let name = CCryptoBoringSSL_X509_NAME_new()

        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "UID", MBSTRING_UTF8, "jsmith", -1, -1, 0)
        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "DC", MBSTRING_UTF8, "example", -1, -1, 0)
        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "DC", MBSTRING_UTF8, "net", -1, -1, 0)

        return name!
    }()

    /// CN=James \"Jim\" Smith\, III,DC=example,DC=net
    /// ME8xHzAdBgNVBAMMFkphbWVzICJKaW0iIFNtaXRoLCBJSUkxFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRMwEQYKCZImiZPyLGQBGRYDbmV0
    /// https://lapo.it/asn1js/#ME8xHzAdBgNVBAMMFkphbWVzICJKaW0iIFNtaXRoLCBJSUkxFzAVBgoJkiaJk_IsZAEZFgdleGFtcGxlMRMwEQYKCZImiZPyLGQBGRYDbmV0
    lazy var jamesSmith: UnsafeMutablePointer<X509_NAME> = {
        let name = CCryptoBoringSSL_X509_NAME_new()

        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, "James \"Jim\" Smith, III", -1, -1, 0)
        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "DC", MBSTRING_UTF8, "example", -1, -1, 0)
        CCryptoBoringSSL_X509_NAME_add_entry_by_txt(name, "DC", MBSTRING_UTF8, "net", -1, -1, 0)

        return name!
    }()

    override func tearDown() {
        CCryptoBoringSSL_X509_NAME_free(joeBloggs)
        CCryptoBoringSSL_X509_NAME_free(jSmith)
        CCryptoBoringSSL_X509_NAME_free(jamesSmith)
        super.tearDown()
    }

    func testDecodingNoDuplicates() {
        var name = BoringSSLX501Name(ref: joeBloggs)

        let country = name.next()
        XCTAssertEqual(country?.0?.shortName, "C")
        XCTAssertEqual(country?.1, "UK")

        let organization = name.next()
        XCTAssertEqual(organization?.0?.shortName, "O")
        XCTAssertEqual(organization?.1, "Disorganized Organization")

        let commonName = name.next()
        XCTAssertEqual(commonName?.0?.shortName, "CN")
        XCTAssertEqual(commonName?.1, "Joe Bloggs")

        XCTAssertNil(name.next())
    }

    func testDuplicates() {
        var name = BoringSSLX501Name(ref: jSmith)

        let userId = name.next()
        XCTAssertEqual(userId?.0?.shortName, "UID")
        XCTAssertEqual(userId?.1, "jsmith")

        let domainComponent = name.next()
        XCTAssertEqual(domainComponent?.0?.shortName, "DC")
        XCTAssertEqual(domainComponent?.1, "example")

        let domainComponent2 = name.next()
        XCTAssertEqual(domainComponent2?.0?.shortName, "DC")
        XCTAssertEqual(domainComponent2?.1, "net")

        XCTAssertNil(name.next())
    }

    func testDuplicatesWithSpecialCharacters() {
        var name = BoringSSLX501Name(ref: jamesSmith)

        let commonName = name.next()
        XCTAssertEqual(commonName?.0?.shortName, "CN")
        XCTAssertEqual(commonName?.1, "James \"Jim\" Smith, III")

        let domainComponent = name.next()
        XCTAssertEqual(domainComponent?.0?.shortName, "DC")
        XCTAssertEqual(domainComponent?.1, "example")

        let domainComponent2 = name.next()
        XCTAssertEqual(domainComponent2?.0?.shortName, "DC")
        XCTAssertEqual(domainComponent2?.1, "net")

        XCTAssertNil(name.next())
    }

}
