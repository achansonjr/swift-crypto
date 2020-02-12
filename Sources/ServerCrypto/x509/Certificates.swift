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
  
  init<S: Sequence>(_ sequence: S) where S.Iterator.Element == Certificate {
    self.contents = [Certificate](sequence)
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
      let iterator = try BIOIterator(PEMBytes: PEMBytes)
      self.contents = [Certificate](AnySequence { iterator })
  }

}
