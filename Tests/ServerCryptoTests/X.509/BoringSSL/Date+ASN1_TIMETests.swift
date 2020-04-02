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

final class Date_ASN1_TIMETests: XCTestCase {

    lazy var asn1TimeEpoch: UnsafeMutablePointer<ASN1_TIME>! = {
        var epochTime = CCryptoBoringSSL_ASN1_TIME_new()
        CCryptoBoringSSL_ASN1_TIME_set(epochTime, 0)
        return epochTime
    }()

    /// The number of seconds from 1 January 1971 to the epoch date, 1 January 1970
    /// Calculated from 86,400 (number of seconds per day) * 365 (number of days in year)
    static let timeIntervalOneYearAfter1970: time_t = 31_536_000

    lazy var asn1TimeOneYearAfterEpoch: UnsafeMutablePointer<ASN1_TIME>! = {
        var epochTime = CCryptoBoringSSL_ASN1_TIME_new()
        CCryptoBoringSSL_ASN1_TIME_set(epochTime, Date_ASN1_TIMETests.timeIntervalOneYearAfter1970)
        return epochTime
    }()

    /// The number of seconds from 1 January 1970 to the reference date, 1 January 2001.
    /// https://github.com/apple/swift-corelibs-foundation/blob/ddae4112622878f83f50d466a943237a84fcaf8b/Sources/Foundation/Date.swift#L23
    static let timeIntervalBetween1970AndReferenceDate: time_t = 978_307_200

    lazy var asn1TimeReferenceDate: UnsafeMutablePointer<ASN1_TIME>! = {
        var epochTime = CCryptoBoringSSL_ASN1_TIME_new()
        CCryptoBoringSSL_ASN1_TIME_set(epochTime, Date_ASN1_TIMETests.timeIntervalBetween1970AndReferenceDate)
        return epochTime
    }()

    override func tearDown() {
        CCryptoBoringSSL_ASN1_TIME_free(asn1TimeEpoch)
        CCryptoBoringSSL_ASN1_TIME_free(asn1TimeOneYearAfterEpoch)
        CCryptoBoringSSL_ASN1_TIME_free(asn1TimeReferenceDate)
        super.tearDown()
    }

    func testInitFromEpoch() {
        // Set date to be 00:00:00 UTC on 1 January 1970
        let date = Date(from: asn1TimeEpoch)
        XCTAssertEqual(date?.timeIntervalSince1970, 0)
        XCTAssertEqual(date?.timeIntervalSinceReferenceDate, -TimeInterval(Date_ASN1_TIMETests.timeIntervalBetween1970AndReferenceDate))
    }

    func testInitOneYearAfterEpoch() {
        // Set date to be 00:00:00 UTC on 1 January 1971
        let date = Date(from: asn1TimeOneYearAfterEpoch)
        XCTAssertEqual(date?.timeIntervalSince1970, TimeInterval(Date_ASN1_TIMETests.timeIntervalOneYearAfter1970))
        XCTAssertEqual(date?.timeIntervalSinceReferenceDate, -TimeInterval(Date_ASN1_TIMETests.timeIntervalBetween1970AndReferenceDate - 31_536_000))
    }

    func testInitFromReferenceDate() {
        // Set date to be 00:00:00 UTC on 1 January 2001
        let date = Date(from: asn1TimeReferenceDate)
        XCTAssertEqual(date?.timeIntervalSince1970, TimeInterval(Date_ASN1_TIMETests.timeIntervalBetween1970AndReferenceDate))
        XCTAssertEqual(date?.timeIntervalSinceReferenceDate, 0)
    }

}
