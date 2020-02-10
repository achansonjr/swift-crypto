//
//  SubjectAltNameSequence.swift
//  
//
//  Created by Lovelett, Ryan A. on 2/10/20.
//

#if compiler(>=5.1) && compiler(<5.3)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
#else
import CCryptoBoringSSL
import CCryptoBoringSSLShims
#endif

/// A helper sequence object that enables us to represent subject alternative names
/// as an iterable Swift sequence.
public class SubjectAltNameSequence: Sequence, IteratorProtocol {
    public typealias Element = Certificate.AlternativeName

    private let nameStack: OpaquePointer
    private var nextIdx: Int
    private let stackSize: Int

    init(nameStack: OpaquePointer) {
        self.nameStack = nameStack
        self.stackSize = CCryptoBoringSSLShims_sk_GENERAL_NAME_num(nameStack)
        self.nextIdx = 0
    }

    public func next() -> Certificate.AlternativeName? {
        guard self.nextIdx < self.stackSize else {
            return nil
        }

        guard let name = CCryptoBoringSSLShims_sk_GENERAL_NAME_value(self.nameStack, self.nextIdx) else {
            fatalError("Unexpected null pointer when unwrapping SAN value")
        }

        self.nextIdx += 1

        switch name.pointee.type {
        case GEN_DNS:
            let namePtr = UnsafeBufferPointer(start: CCryptoBoringSSL_ASN1_STRING_get0_data(name.pointee.d.ia5),
                                              count: Int(CCryptoBoringSSL_ASN1_STRING_length(name.pointee.d.ia5)))
            let nameString = [UInt8](namePtr)
            return .dnsName(nameString)
        case GEN_IPADD:
            let addrPtr = UnsafeBufferPointer(start: CCryptoBoringSSL_ASN1_STRING_get0_data(name.pointee.d.ia5),
                                              count: Int(CCryptoBoringSSL_ASN1_STRING_length(name.pointee.d.ia5)))
            guard let addr = Certificate.IPAddress(addressFromBytes: addrPtr) else {
                // This should throw, but we can't throw from next(). Skip this instead.
                return self.next()
            }
            return .ipAddress(addr)
        default:
            // We don't recognise this name type. Skip it.
            return next()
        }
    }

    deinit {
        CCryptoBoringSSL_GENERAL_NAMES_free(self.nameStack)
    }
}

