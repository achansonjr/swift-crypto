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
import Foundation

internal extension Date {

    /// Returns a `Date` initialized from the provided `ASN1_TIME`.
    ///
    /// The date is calulated using the difference between the provided `ASN1_TIME` and `Date`'s internal reference date
    /// 00:00:00 UTC on 1 January 2001 [1]. To calculate the difference between those two dates a new `ASN1_TIME` is
    /// created that represents 00:00:00 UTC on 1 January 2001 and `ASN1_TIME_diff` is used to calculate the difference.
    /// This implementation was suggested by Dr. Stephen N Henson, a core developer of the OpenSSL project [2].
    ///
    /// [1] https://github.com/apple/swift-corelibs-foundation/blob/ddae4112622878f83f50d466a943237a84fcaf8b/Sources/Foundation/Date.swift#L56-L58
    /// [2] https://mta.openssl.org/pipermail/openssl-users/2017-September/006453.html
    init?(from pointer: UnsafePointer<ASN1_TIME>) {
        var referenceTime = CCryptoBoringSSL_ASN1_TIME_new()
        defer {
            CCryptoBoringSSL_ASN1_TIME_free(referenceTime)
        }
        CCryptoBoringSSL_ASN1_TIME_set(referenceTime, Int(Date.timeIntervalBetween1970AndReferenceDate))

        var days: CInt = 0
        var seconds: CInt = 0
        guard CCryptoBoringSSL_ASN1_TIME_diff(&days, &seconds, referenceTime, pointer) == 1 else {
            return nil
        }
        // 86_400 is the number of seconds in a day
        let interval = TimeInterval(days * 86400 + seconds)
        self.init(timeIntervalSinceReferenceDate: interval)
    }

}
