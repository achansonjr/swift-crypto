//
//  Certificates.swift
//  
//
//  Created by Hanson, Anthony C. Jr on 2/12/20.
//

#if compiler(>=5.1) && compiler(<5.3)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
#else
import CCryptoBoringSSL
import CCryptoBoringSSLShims
#endif
import Foundation

struct Certificates {
  fileprivate var contents: [Certificate] = []

  var totalCount: Int {
    return contents.count
  }
  
  init<S: Sequence>(_ sequence: S) where S.Iterator.Element == Certificate {
    for element in sequence {
      add(element)
    }
  }

  mutating func add(_ member: Certificate) {
    contents.append(member)
  }
  
  mutating func remove(_ member: Certificate) {
    guard let index = contents.firstIndex(of: member) else {
      return
    }
    
    contents.remove(at: index)
  }
  
}

extension Certificates: Equatable {}

extension Certificates: CustomStringConvertible {
  var description: String {
    return String(describing: contents)
  }
}

extension Certificates: ExpressibleByArrayLiteral {
  init(arrayLiteral elements: Certificate...) {
    self.init(elements)
  }
}

extension Certificates: Sequence {
  typealias Iterator = AnyIterator<Certificate>

  func makeIterator() -> Iterator {
    var iterator = contents.makeIterator()
    return AnyIterator {
      return iterator.next()
    }
  }
}

extension Certificates: Collection {
  typealias Index = Int

  var startIndex: Index {
    return contents.startIndex
  }

  var endIndex: Index {
    return contents.endIndex
  }

  subscript (position: Index) -> Iterator.Element {
    precondition(indices.contains(position), "out of bounds")
    return contents[position]
  }

  func index(after i: Index) -> Index {
    return contents.index(after: i)
  }
}

extension Certificates {
  /// Create an array of `Certificate`s from a buffer of bytes in PEM format.
  ///
  /// - Parameter bytes: The PEM buffer to read certificates from.
  /// - Throws: If an error is encountered while reading certificates.
  init<B: ContiguousBytes>(PEMBytes: B) throws {
      CCryptoBoringSSL_ERR_clear_error()
      defer {
          CCryptoBoringSSL_ERR_clear_error()
      }

      self = try PEMBytes.withUnsafeBytes { (ptr) -> Certificates in
          let bio = CCryptoBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!
          defer {
              CCryptoBoringSSL_BIO_free(bio)
          }
          return try createCertificates(fromBIO: bio)
      }
  }

  /// Reads `Certificate`s from the given BIO.
  internal func createCertificates(fromBIO: UnsafeMutablePointer<BIO>) throws -> Certificates {
      guard let x509 = CCryptoBoringSSL_PEM_read_bio_X509_AUX(fromBIO, nil, nil, nil) else {
          throw CryptoCertificateError.failedToLoadCertificate
      }

      // var certificates = [Certificate(withOwnedReference: x509)]
      var certificates: Certificates = Certificates()
      certificates.add(Certificate(withOwnedReference: x509))
    
      while let x = CCryptoBoringSSL_PEM_read_bio_X509(fromBIO, nil, nil, nil) {
          certificates.add(Certificate(withOwnedReference: x))
      }

      let err = CCryptoBoringSSL_ERR_peek_error()

      // If we hit the end of the file then it's not a real error, we just read as much as we could.
      if CCryptoBoringSSLShims_ERR_GET_LIB(err) == ERR_LIB_PEM && CCryptoBoringSSLShims_ERR_GET_REASON(err) == PEM_R_NO_START_LINE {
          CCryptoBoringSSL_ERR_clear_error()
      } else {
          throw CryptoCertificateError.failedToLoadCertificate
      }

      // self = certificates
      return certificates
  }
}
