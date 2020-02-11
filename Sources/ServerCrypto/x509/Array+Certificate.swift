//
//  File.swift
//  
//
//  Created by Hanson, Anthony C. Jr on 2/11/20.
//
#if compiler(>=5.1) && compiler(<5.3)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
#else
import CCryptoBoringSSL
import CCryptoBoringSSLShims
#endif
import Foundation

extension Array where Element == Certificate {
  /// Create an array of `Certificate`s from a file at a given path in PEM format.
  ///
  /// - Parameter file: The PEM file to read certificates from.
  /// - Throws: If an error is encountered while reading certificates.
  init(withPEMPathString: String) throws {
      let pemURL = URL(fileURLWithPath: withPEMPathString)
      let data = try Data(contentsOf: pemURL)
      self = try Array(fromPEMBytes: data)
//      CCryptoBoringSSL_ERR_clear_error()
//      defer {
//          CCryptoBoringSSL_ERR_clear_error()
//      }
//
//      guard let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_file()) else {
//          throw CryptoCertificateError.unableToAllocateBoringSSLObject
//      }
//      defer {
//          CCryptoBoringSSL_BIO_free(bio)
//      }
//
//      guard CCryptoBoringSSL_BIO_read_filename(bio, fromPathFile) > 0 else {
//          throw CryptoCertificateError.failedToLoadCertificate
//      }
//
//      self = try Array(fromBIO: bio)
  }

  /// Reads `Certificate`s from the given BIO.
  init(fromBIO: UnsafeMutablePointer<BIO>) throws {
      guard let x509 = CCryptoBoringSSL_PEM_read_bio_X509_AUX(fromBIO, nil, nil, nil) else {
          throw CryptoCertificateError.failedToLoadCertificate
      }

      var certificates = [Certificate(withOwnedReference: x509)]

      while let x = CCryptoBoringSSL_PEM_read_bio_X509(fromBIO, nil, nil, nil) {
          certificates.append(.init(withOwnedReference: x))
      }

      let err = CCryptoBoringSSL_ERR_peek_error()

      // If we hit the end of the file then it's not a real error, we just read as much as we could.
      if CCryptoBoringSSLShims_ERR_GET_LIB(err) == ERR_LIB_PEM && CCryptoBoringSSLShims_ERR_GET_REASON(err) == PEM_R_NO_START_LINE {
          CCryptoBoringSSL_ERR_clear_error()
      } else {
          throw CryptoCertificateError.failedToLoadCertificate
      }

      self = certificates
  }

  /// Create an array of `Certificate`s from a buffer of bytes in PEM format.
  ///
  /// - Parameter bytes: The PEM buffer to read certificates from.
  /// - Throws: If an error is encountered while reading certificates.
  init<B: ContiguousBytes>(fromPEMBytes: B) throws {
      CCryptoBoringSSL_ERR_clear_error()
      defer {
          CCryptoBoringSSL_ERR_clear_error()
      }

      self = try fromPEMBytes.withUnsafeBytes { (ptr) -> [Certificate] in
          let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!
          defer {
              CCryptoBoringSSL_BIO_free(bio)
          }

          return try Array(fromBIO: bio)
      }
  }
}
