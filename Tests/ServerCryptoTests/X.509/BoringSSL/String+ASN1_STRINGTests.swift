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

private let fixture: StaticString = "It is a far, far better thing that I do, than I have ever done"

final class String_ASN1_StringTests: XCTestCase {

    lazy var octet: UnsafeMutablePointer<ASN1_STRING> = {
        // V_ASN1_OCTETSTRING
        let string = CCryptoBoringSSL_ASN1_STRING_new()
        CCryptoBoringSSL_ASN1_STRING_set(string, fixture.utf8Start, Int32(fixture.utf8CodeUnitCount))
        return string!
    }()

    lazy var printable: UnsafeMutablePointer<ASN1_STRING> = {
        let string = CCryptoBoringSSL_ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING)
        CCryptoBoringSSL_ASN1_STRING_set(string, fixture.utf8Start, Int32(fixture.utf8CodeUnitCount))
        return string!
    }()

    lazy var utf8: UnsafeMutablePointer<ASN1_STRING> = {
        let string = CCryptoBoringSSL_ASN1_STRING_type_new(V_ASN1_UTF8STRING)
        CCryptoBoringSSL_ASN1_STRING_set(string, fixture.utf8Start, Int32(fixture.utf8CodeUnitCount))
        return string!
    }()

    lazy var empty: UnsafeMutablePointer<ASN1_STRING> = {
        let string = CCryptoBoringSSL_ASN1_STRING_new()
        CCryptoBoringSSL_ASN1_STRING_set(string, "", 0)
        return string!
    }()

    lazy var unset: UnsafeMutablePointer<ASN1_STRING> = {
        let string = CCryptoBoringSSL_ASN1_STRING_new()
        return string!
    }()

    override func tearDown() {
        CCryptoBoringSSL_ASN1_STRING_free(octet)
        CCryptoBoringSSL_ASN1_STRING_free(printable)
        CCryptoBoringSSL_ASN1_STRING_free(utf8)
        CCryptoBoringSSL_ASN1_STRING_free(empty)
        CCryptoBoringSSL_ASN1_STRING_free(unset)
        super.tearDown()
    }

    func testConvertOctet() {
        let string = String(from: octet)
        XCTAssertEqual(string, fixture.description)
    }

    func testConvertPrintable() {
        let string = String(from: printable)
        XCTAssertEqual(string, fixture.description)
    }

    func testConvertUTF8() {
        let string = String(from: utf8)
        XCTAssertEqual(string, fixture.description)
    }

    func testEmptyString() {
        let string = String(from: empty)
        XCTAssertEqual(string, "")
    }

    func testUnsetString() {
        let string = String(from: unset)
        XCTAssertNil(string)
    }
}
