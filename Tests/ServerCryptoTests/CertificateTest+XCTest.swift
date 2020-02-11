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
//
// SSLCertificateTest+XCTest.swift
//
import XCTest

///
/// NOTE: This file was generated by generate_linux_tests.rb
///
/// Do NOT edit this file directly as it will be regenerated automatically when needed.
///

extension CertificateTest {

   @available(*, deprecated, message: "not actually deprecated. Just deprecated to allow deprecated tests (which test deprecated functionality) without warnings")
   static var allTests : [(String, (CertificateTest) -> () throws -> Void)] {
      return [
                ("testLoadingPemCertFromFile", testLoadingPemCertFromFile),
                ("testLoadingDerCertFromFile", testLoadingDerCertFromFile),
                ("testDerAndPemAreIdentical", testDerAndPemAreIdentical),
                ("testLoadingPemCertFromMemory", testLoadingPemCertFromMemory),
                ("testPemLoadingMechanismsAreIdentical", testPemLoadingMechanismsAreIdentical),
                ("testLoadingPemCertsFromMemory", testLoadingPemCertsFromMemory),
                ("testLoadingPemCertsFromFile", testLoadingPemCertsFromFile),
                ("testLoadingDerCertFromMemory", testLoadingDerCertFromMemory),
                ("testLoadingGibberishFromMemoryAsPemFails", testLoadingGibberishFromMemoryAsPemFails),
                ("testLoadingGibberishFromPEMBufferFails", testLoadingGibberishFromPEMBufferFails),
                ("testLoadingGibberishFromMemoryAsDerFails", testLoadingGibberishFromMemoryAsDerFails),
                ("testLoadingGibberishFromFileAsPemFails", testLoadingGibberishFromFileAsPemFails),
                ("testLoadingGibberishFromPEMFileFails", testLoadingGibberishFromPEMFileFails),
                ("testLoadingGibberishFromFileAsDerFails", testLoadingGibberishFromFileAsDerFails),
                ("testLoadingNonexistentFileAsPem", testLoadingNonexistentFileAsPem),
                ("testLoadingNonexistentPEMFile", testLoadingNonexistentPEMFile),
                ("testLoadingNonexistentFileAsDer", testLoadingNonexistentFileAsDer),
                ("testEnumeratingSanFields", testEnumeratingSanFields),
                ("testNonexistentSan", testNonexistentSan),
                ("testCommonName", testCommonName),
                ("testMultipleCommonNames", testMultipleCommonNames),
                ("testNoCommonName", testNoCommonName),
                ("testUnicodeCommonName", testUnicodeCommonName),
                ("testExtractingPublicKey", testExtractingPublicKey),
                ("testDumpingPEMCert", testDumpingPEMCert),
                ("testDumpingDERCert", testDumpingDERCert),
           ]
   }
}

