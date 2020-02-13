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

final class BIOIterator {

  private var bio: UnsafeMutablePointer<BIO>?

  convenience init(pem: String) throws {
    guard let pemData = pem.data(using: .utf8) else {
      throw CryptoCertificateError.failedToLoadCertificate
    }
    try self.init(PEMBytes: pemData)
  }

  convenience init<B: ContiguousBytes>(PEMBytes: B) throws {
    CCryptoBoringSSL_ERR_clear_error()
    defer {
        CCryptoBoringSSL_ERR_clear_error()
    }

    let localBio = PEMBytes.withUnsafeBytes { CCryptoBoringSSL_BIO_new_mem_buf($0.baseAddress, CInt($0.count))!
    }

    self.init(fromBIO: localBio)
  }

  init(fromBIO: UnsafeMutablePointer<BIO>) {
    bio = fromBIO
  }

  deinit {
    CCryptoBoringSSL_BIO_free(bio)
  }

}

extension BIOIterator: IteratorProtocol {

  func next() -> Certificate? {
    if let foo = CCryptoBoringSSL_PEM_read_bio_X509_AUX(bio, nil, nil, nil) {
      return Certificate(withOwnedReference: foo)
    } else {
      let err = CCryptoBoringSSL_ERR_peek_error()

      // If we hit the end of the file then it's not a real error, we just read as much as we could.
      if CCryptoBoringSSLShims_ERR_GET_LIB(err) == ERR_LIB_PEM && CCryptoBoringSSLShims_ERR_GET_REASON(err) == PEM_R_NO_START_LINE {
          CCryptoBoringSSL_ERR_clear_error()
      } else {
          throw CryptoCertificateError.failedToLoadCertificate
      }
    }
  }

}
