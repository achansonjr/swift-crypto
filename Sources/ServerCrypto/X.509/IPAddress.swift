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
import Foundation

public struct IPAddress: Equatable {
    enum Address: CustomStringConvertible, Equatable {
        case ipv4(in_addr)
        case ipv6(in6_addr)
    }

    private let address: Address

    init(_ address: Address) {
        self.address = address
    }

    init?(copyingBytesFrom bytes: UnsafeBufferPointer<UInt8>) {
        guard let addr = Address(addressFromBytes: bytes) else {
            return nil
        }
        self.init(addr)
    }

    public var description: String {
        address.description
    }
}

// MARK: - Private Extension to Handle Creating Address

extension IPAddress.Address {
    init?(addressFromBytes bytes: UnsafeBufferPointer<UInt8>) {
        switch bytes.count {
        case MemoryLayout<in_addr>.size: // 4 bytes
            precondition(MemoryLayout<in_addr>.stride == MemoryLayout<in_addr>.size)
            var mutable = in_addr()
            _ = withUnsafeMutableBytes(of: &mutable) {
                bytes.copyBytes(to: $0)
            }

            self = .ipv4(mutable)
        case MemoryLayout<in6_addr>.size: // 16
            var mutable = in6_addr()
            _ = withUnsafeMutableBytes(of: &mutable) {
                bytes.copyBytes(to: $0)
            }

            self = .ipv6(mutable)
        default:
            return nil
        }
    }

    var description: String {
        switch self {
        case .ipv4(var mutable):
            let length: socklen_t = socklen_t(INET_ADDRSTRLEN)
            let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(length))
            defer {
                buffer.deallocate()
            }
            guard inet_ntop(AF_INET, &mutable, buffer, length) != nil else {
                let errsv = errno
                let message = String(errno: errsv)
                return "inet_ntop failed; errno=\(errsv), message=\(message)"
            }
            return String(cString: buffer)
        case .ipv6(var mutable):
            let length: socklen_t = socklen_t(INET6_ADDRSTRLEN)
            let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(length))
            defer {
                buffer.deallocate()
            }
            guard inet_ntop(AF_INET6, &mutable, buffer, length) != nil else {
                let errsv = errno
                let message = String(errno: errsv)
                return "inet_ntop failed; errno=\(errsv), message=\(message)"
            }
            return String(cString: buffer)
        }
    }

    static func == (lhs: IPAddress.Address, rhs: IPAddress.Address) -> Bool {
        switch (lhs, rhs) {
        case (.ipv4(let lhsAddr), ipv4(let rhsAddr)):
            return lhsAddr.s_addr == rhsAddr.s_addr
        case (.ipv6(let lhsAddr), ipv6(let rhsAddr)):
            return lhsAddr.__u6_addr.__u6_addr32 == rhsAddr.__u6_addr.__u6_addr32
        default:
            return false
        }
    }
}

// MARK: - Private Extension to String to Handle Converting errno to Printable String

private extension String {
    init(errno errsv: errno_t, capacity: Int = 256) {
        let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
        defer {
            buffer.deallocate()
        }
        let returnValue = strerror_r(errsv, buffer, capacity)
        if returnValue == 0 {
            // The XSI-compliant strerror_r() function returns 0 on success.
            self.init(cString: buffer)
        } else if returnValue < 0 {
            // or -1 is returned and errno is set to indicate the error (glibc versions before 2.13)
            self.init(errno: errno, capacity: capacity)
        } else {
            // On error, a (positive) error number is returned (since glibc 2.13)
            self = "Unknown error \(returnValue)"
        }
    }
}
