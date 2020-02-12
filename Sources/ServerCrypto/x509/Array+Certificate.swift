////
////  File.swift
////  
////
////  Created by Hanson, Anthony C. Jr on 2/11/20.
////
//#if compiler(>=5.1) && compiler(<5.3)
//@_implementationOnly import CCryptoBoringSSL
//@_implementationOnly import CCryptoBoringSSLShims
//#else
//import CCryptoBoringSSL
//import CCryptoBoringSSLShims
//#endif
//import Foundation
//
//public extension AnyCollection where Iterator.Element == Certificate {
// 
//  /// Create an array of `Certificate`s from a buffer of bytes in PEM format.
//  ///
//  /// - Parameter bytes: The PEM buffer to read certificates from.
//  /// - Throws: If an error is encountered while reading certificates.
//  init<B: ContiguousBytes>(PEMBytes: B) throws {
//      CCryptoBoringSSL_ERR_clear_error()
//      defer {
//          CCryptoBoringSSL_ERR_clear_error()
//      }
//
//      self = AnyCollection(Array<Certificate>())
//      let baz = try PEMBytes.withUnsafeBytes { (ptr) -> AnyCollection<Certificate> in
//          let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!
//          defer {
//              CCryptoBoringSSL_BIO_free(bio)
//          }
//          let certs = try createCertificates(fromBIO: bio)
//          return AnyCollection(certs)
//      }
//    
//  }
//
//  /// Reads `Certificate`s from the given BIO.
//  internal func createCertificates(fromBIO: UnsafeMutablePointer<BIO>) throws -> Certificates<Certificate> {
//      guard let x509 = CCryptoBoringSSL_PEM_read_bio_X509_AUX(fromBIO, nil, nil, nil) else {
//          throw CryptoCertificateError.failedToLoadCertificate
//      }
//
//      // var certificates = [Certificate(withOwnedReference: x509)]
//      var certificates: Certificates = Certificates<Certificate>()
//      certificates.add(Certificate(withOwnedReference: x509))
//    
//      while let x = CCryptoBoringSSL_PEM_read_bio_X509(fromBIO, nil, nil, nil) {
//          certificates.add(Certificate(withOwnedReference: x))
//      }
//
//      let err = CCryptoBoringSSL_ERR_peek_error()
//
//      // If we hit the end of the file then it's not a real error, we just read as much as we could.
//      if CCryptoBoringSSLShims_ERR_GET_LIB(err) == ERR_LIB_PEM && CCryptoBoringSSLShims_ERR_GET_REASON(err) == PEM_R_NO_START_LINE {
//          CCryptoBoringSSL_ERR_clear_error()
//      } else {
//          throw CryptoCertificateError.failedToLoadCertificate
//      }
//
//      // self = certificates
//      return certificates
//  }
//}
