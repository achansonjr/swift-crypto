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
import XCTest

let samplePemCert = """
-----BEGIN CERTIFICATE-----
MIIGGzCCBAOgAwIBAgIJAJ/X0Fo0ynmEMA0GCSqGSIb3DQEBCwUAMIGjMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5z
b2t5bzEuMCwGA1UECgwlU2FuIEZyYW5zb2t5byBJbnN0aXR1dGUgb2YgVGVjaG5v
bG9neTEVMBMGA1UECwwMUm9ib3RpY3MgTGFiMSAwHgYDVQQDDBdyb2JvdHMuc2Fu
ZnJhbnNva3lvLmVkdTAeFw0xNzEwMTYyMTAxMDJaFw00NzEwMDkyMTAxMDJaMIGj
MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2Fu
IEZyYW5zb2t5bzEuMCwGA1UECgwlU2FuIEZyYW5zb2t5byBJbnN0aXR1dGUgb2Yg
VGVjaG5vbG9neTEVMBMGA1UECwwMUm9ib3RpY3MgTGFiMSAwHgYDVQQDDBdyb2Jv
dHMuc2FuZnJhbnNva3lvLmVkdTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAO9rzJOOE8cmsIqAJMCrHDxkBAMgZhMsJ863MnWtVz5JIJK6CKI/Nu26tEzo
kHy3EI9565RwikvauheMsWaTFA4PD/P+s1DtxRCGIcK5x+SoTN7Drn5ZueoJNZRf
TYuN+gwyhprzrZrYjXpvEVPYuSIeUqK5XGrTyFA2uGj9wY3f9IF4rd7JT0ewRb1U
8OcR7xQbXKGjkY4iJE1TyfmIsBZboKaG/aYa9KbnWyTkDssaELWUIKrjwwuPgVgS
vlAYmo12MlsGEzkO9z78jvFmhUOsaEldM8Ua2AhOKW0oSYgauVuro/Ap/o5zn8PD
IDapl9g+5vjN2LucqX2a9utoFvxSKXT4NvfpL9fJvzdBNMM4xpqtHIkV0fkiMbWk
EW2FFlOXKnIJV8wT4a9iduuIDMg8O7oc+gt9pG9MHTWthXm4S29DARTqfZ48bW77
z8RrEURV03o05b/twuAJSRyyOCUi61yMo3YNytebjY2W3Pxqpq+YmT5qhqBZDLlT
LMptuFdISv6SQgg7JoFHGMWRXUavMj/sn5qZD4pQyZToHJ2Vtg5W/MI1pKwc3oKD
6M3/7Gf35r92V/ox6XT7+fnEsAH8AtQiZJkEbvzJ5lpUihSIaV3a/S+jnk7Lw8Tp
vjtpfjOg+wBblc38Oa9tk2WdXwYDbnvbeL26WmyHwQTUBi1jAgMBAAGjUDBOMB0G
A1UdDgQWBBToPRmTBQEF5F5LcPiUI5qBNPBU+DAfBgNVHSMEGDAWgBToPRmTBQEF
5F5LcPiUI5qBNPBU+DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCY
gxM5lufF2lTB9sH0s1E1VTERv37qoapNP+aw06oZkAD67QOTXFzbsM3JU1diY6rV
Y0g9CLzRO7gZY+kmi1WWnsYiMMSIGjIfsB8S+ot43LME+AJXPVeDZQnoZ6KQ/9r+
71Umi4AKLoZ9dInyUIM3EHg9pg5B0eEINrh4J+OPGtlC3NMiWxdmIkZwzfXa+64Z
8k5aX5piMTI+9BQSMWw5l7tFT/PISuI8b/Ln4IUBXKA0xkONXVnjPOmS0h7MBoc2
EipChDKnK+Mtm9GQewOCKdS2nsrCndGkIBnUix4ConUYIoywVzWGMD+9OzKNg76d
O6A7MxdjEdKhf1JDvklxInntDUDTlSFL4iEFELwyRseoTzj8vJE+cL6h6ClasYQ6
p0EeL3UpICYerfIvPhohftCivCH3k7Q1BSf0fq73cQ55nrFAHrqqYjD7HBeBS9hn
3L6bz9Eo6U9cuxX42k3l1N44BmgcDPin0+CRTirEmahUMb3gmvoSZqQ3Cz86GkIg
7cNJosc9NyevQlU9SX3ptEbv33tZtlB5GwgZ2hiGBTY0C3HaVFjLpQiSS5ygZLgI
/+AKtah7sTHIAtpUH1ZZEgKPl1Hg6J4x/dBkuk3wxPommNHaYaHREXF+fHMhBrSi
yH8agBmmECpa21SVnr7vrL+KSqfuF+GxwjSNsSR4SA==
-----END CERTIFICATE-----
"""

let sampleDerCertSPKI = Array(Data(base64Encoded: """
'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA72vMk44TxyawioAkwKscPGQEAyBmEywnzrcyda1XPkkgkroIoj827bq0TOiQfLcQj3nrlHCKS9q6F4yxZpMUDg8P8/6zUO3FEIYhwrnH5KhM3sOuflm56gk1lF9Ni436DDKGmvOtmtiNem8RU9i5Ih5SorlcatPIUDa4aP3Bjd/0gXit3slPR7BFvVTw5xHvFBtcoaORjiIkTVPJ+YiwFlugpob9phr0pudbJOQOyxoQtZQgquPDC4+BWBK+UBiajXYyWwYTOQ73PvyO8WaFQ6xoSV0zxRrYCE4pbShJiBq5W6uj8Cn+jnOfw8MgNqmX2D7m+M3Yu5ypfZr262gW/FIpdPg29+kv18m/N0E0wzjGmq0ciRXR+SIxtaQRbYUWU5cqcglXzBPhr2J264gMyDw7uhz6C32kb0wdNa2FebhLb0MBFOp9njxtbvvPxGsRRFXTejTlv+3C4AlJHLI4JSLrXIyjdg3K15uNjZbc/Gqmr5iZPmqGoFkMuVMsym24V0hK/pJCCDsmgUcYxZFdRq8yP+yfmpkPilDJlOgcnZW2Dlb8wjWkrBzegoPozf/sZ/fmv3ZX+jHpdPv5+cSwAfwC1CJkmQRu/MnmWlSKFIhpXdr9L6OeTsvDxOm+O2l+M6D7AFuVzfw5r22TZZ1fBgNue9t4vbpabIfBBNQGLWMCAwEAAQ=='
""", options: .ignoreUnknownCharacters)!)

let multiSanCert = """
-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIURiMaUmhI1Xr0mZ4p+JmI0XjZTaIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE3MTAzMDEyMDUwMFoXDTQwMDEw
MTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA26DcKAxqdWivhS/J3Klf+cEnrT2cDzLhmVRCHuQZXiIr
tqr5401KDbRTVOg8v2qIyd8x4+YbpE47JP3fBrcMey70UK/Er8nu28RY3z7gZLLi
Yf+obHdDFCK5JaCGmM61I0c0vp7aMXsyv7h3vjEzTuBMlKR8p37ftaXSUAe3Qk/D
/fzA3k02E2e3ap0Sapd/wUu/0n/MFyy9HkkeykivAzLaaFhhvp3hATdFYC4FLld8
OMB60bC2S13CAljpMlpjU/XLLOUbaPgnNUqE1nFqFBoTl6kV6+ii8Dd5ENVvE7pE
SoNoyGLDUkDRJJMNUHAo0zbxyhd7WOtyZ7B4YBbPswIDAQABo10wWzBLBgNVHREE
RDBCgglsb2NhbGhvc3SCC2V4YW1wbGUuY29tgRB1c2VyQGV4YW1wbGUuY29thwTA
qAABhxAgAQ24AAAAAAAAAAAAAAABMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
BQADggEBACYBArIoL9ZzVX3M+WmTD5epmGEffrH7diRJZsfpVXi86brBPrbvpTBx
Fa+ZKxBAchPnWn4rxoWVJmTm4WYqZljek7oQKzidu88rMTbsxHA+/qyVPVlQ898I
hgnW4h3FFapKOFqq5Hj2gKKItFIcGoVY2oLTBFkyfAx0ofromGQp3fh58KlPhC0W
GX1nFCea74mGyq60X86aEWiyecYYj5AEcaDrTnGg3HLGTsD3mh8SUZPAda13rO4+
RGtGsA1C9Yovlu9a6pWLgephYJ73XYPmRIGgM64fkUbSuvXNJMYbWnzpoCdW6hka
IEaDUul/WnIkn/JZx8n+wgoWtyQa4EA=
-----END CERTIFICATE-----
"""

let multiCNCert = """
-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIUR6eOMdEFZAqorykK6u6rwPGfsh0wDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCVVMxEjAQBgNVBAMMCUlnbm9yZSBtZTERMA8GA1UECAwI
TmVicmFza2ExEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xNzExMDIxMzM5MjRaFw00
MDAxMDEwMDAwMDBaMEgxCzAJBgNVBAYTAlVTMRIwEAYDVQQDDAlJZ25vcmUgbWUx
ETAPBgNVBAgMCE5lYnJhc2thMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCb/wE6/pF40KmF4bgtrlInWIojsDma08q7
cK9LpzifjYNTrlTv7+8tR3TRkWwThW4sMGckq9u1Bty9aF50sazBZaLDZYoamuHS
43T7hj4aX++lEq+inlXaNX3WmKkq0y0ANLBsXaLC+8J+xemlXErBsacK1Lz8Yz//
lVOwD85LG6UN87j8L/L5+t922HyGhQRVTvcbmXa05JovMXILXnoUeEvNteZZtLa0
zcpO+9pN/VwmxVOnQncxTG81FV6Qypx7YFf16QyEDVkXrt7/l6k+I+sAzBHIn28Y
cPq/HfcAbWPU+gMiCLCplDi5NCyL7yyiG7bEjxR0oiWhzZG1abgjAgMBAAGjEDAO
MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFAknMMePElmNsuzEUWO
m2a6n/cHEaJzDEVLbFifcCUNU2U6o2bgXrJIBjFudISYPjpG+gmnuAwdfu6CA63M
wiuLaLQASz6W12pRqlIriUazDn4JnIHu8wCHj8QkYTV7HunhtGJjX7xT89dRS5Y/
IJv0Q9J2CZ16d3ETCzWp2Djq1IPggkBrsgKalJmwsiWi8UkH/GeMA+YQ1p8r9Bvp
+Jd1VitqxJFG5tgT68dq1LxlsNb4L1Cm15m8LdhY5BgSO2AG9G4gBbO0ixZJwHbn
TLiPC0Jd3x5tf9qeSv1eWHuhQd9R908EhZdC6rgN8fZfMux2tQxNbIsNPYAQhmsB
/nc=
-----END CERTIFICATE-----
"""

let noCNCert = """
-----BEGIN CERTIFICATE-----
MIIC3jCCAcagAwIBAgIUeB9gFXDDe/kTcsPGlHIZ4M+SpyYwDQYJKoZIhvcNAQEL
BQAwIDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5lYnJhc2thMB4XDTE3MTEwMjEz
NDIwMFoXDTQwMDEwMTAwMDAwMFowIDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
YnJhc2thMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2DqRr+tIXVXz
4VZA5dSJo4pPgC+lNngg8Bpk9pedmOj8GSdvbIkRmXPRqOIw33vurfGVqcYiX3DH
HcVKS6ZF/ylE4dDH7JmGvCYpJTK6+02nkpdz3CzoX8lIRHBSJAJwny/UK20QBhsU
OWm/mD0uCRfgfp9FasKqA56OBFGNYAOTAM33RHuXQNSSfV5FmSmNkWsiM1S+EUgH
PptKQlXUfiSUFBCuyy9iItSg2fOew3C6/dXJ47T4mFi5qD/WKmI3uSNqBKNPcHI8
EGZX4r8w0Hvq2hV13t+hexaLkS6VeZWb1kTrdgDPnjcl43txePPP7tEGRlZFO+bI
V2j0pGb/iwIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB
AQC27ElJn7TWhr2WcPsdXxGNUpepFgXEsEAVnoiJPI9XqXdOZCFWTUmRXrQICPUn
8HnVfYTFl/WZnTYhf8Ky5RB1W3X0Juo7MGge7mx6D6m8yJVBecQxPasVienTvdDg
UZI2oodxnS7egFwlvFM2ZUmPLVvq0B7VQBSa2Ix3FChNtJ1u5yfHyoDUMRfYl0bF
0B3poAgLDW3FUQ7QoErMvslUJrFxmJXUKKdhg9z6jQTdcmZ6Dr8sFZQkRADbJRzm
AYqSreeyevxdoNwQrpZMAGm61nc7OS8i0Q0JRe3FpGD29BMS0ystlzDeNnUpf+yJ
u9dFQrCkq8MilGSO1L2bZsqY
-----END CERTIFICATE-----
"""

let unicodeCNCert = """
-----BEGIN CERTIFICATE-----
MIICyjCCAbKgAwIBAgIUeK7KUVK7tcUhxVnkSWEsqHj07TEwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLc3RyYcOfZS5vcmcwHhcNMTcxMTAyMTM0NzQxWhcNNDAw
MTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtzdHJhw59lLm9yZzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAO0Anpw+WpM897YXUNHI4oTr4BUxIcOC2A7LQiQ0
briNXLIaIN8irwaa4TwCqvjg2B09GGO7EWvi0EX050X0jFFiSDdGhSZGMLL34nfk
/HW14XjTCW+LkYcFAyOD8Kf3nGGLagIdtnPWQ3Atf6rTf5A35K75+penURN226xB
t0vKqtngYTFu0n6B/+Ip6FI/Bq8yyGtPN74yR79KG3WL7mvrEHxv+TnZkb2F6f2j
cJALEJPx8wFug154EnRDOURZMX5gmHRR/Xm9jP1R7Rch+4Ue2Fy38C1a35p0Saap
JDKSmxr2430bQ5S41BTT5Q3N6eBD7f+cqaQyoa0u+qvl+gcCAwEAAaMQMA4wDAYD
VR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAM7x+J+A2UN+RCKEjJUc9rM3S
G9AxfhKO3VN1mrPRs6JG1ED7t/9e2xdjLRRl84Rz9jnaKVTS2sQ8yKYejWGUbXDq
WO6KNlrjzspL3M8EIoi7QNwtRktviCkkxxwhzDfuH9N6ncjq0qod0vxGq0nqxrAo
VJto6NnrshZEQHGF8uipOFPNTDAR0SpzyzXaK59oqSPJ5VrZiQ3p8izVuRE9r1u2
i5PCcPYi39q101UIxV/WokS0mqHx/XuTYTwhWYd/C49OnM8MLZOUJd8w0VvS0ItY
/wAv4vk0ScS4KmXTJBBGSiBqLdroaM9VKcA1p7TN0vzlut2E/nKmBhgzQJFKZA==
-----END CERTIFICATE-----
"""

func assertNoThrowWithValue<T>(_ body: @autoclosure () throws -> T, defaultValue: T? = nil, file: StaticString = #file, line: UInt = #line) throws -> T {
    do {
        return try body()
    } catch {
        XCTFail("unexpected error \(error) thrown", file: file, line: line)
        if let defaultValue = defaultValue {
            return defaultValue
        } else {
            throw error
        }
    }
}

let samplePemCerts = "\(samplePemCert)\n\(samplePemCert)"
let sampleDerCert = pemToDer(samplePemCert)
// No DER version of the private key becuase encrypted DERs aren't real.

func pemToDer(_ pem: String) -> Data {
    var lines = [String]()

    // This is very inefficient, but it doesn't really matter because this
    // code is run very infrequently and only in testing. Blame the inefficiency
    // on Linux Foundation, which currently lacks String.enumerateLines.
    let originalLines = pem.split(separator: "\n")
    for line in originalLines {
        let line = String(line)
        if !line.hasPrefix("-----") {
            lines.append(line)
        }
    }

    let encodedData = lines.joined(separator: "")
    return Data(base64Encoded: encodedData)!
}

func makeTemporaryFile(fileExtension: String = "") -> String {
    let template = "/tmp/niotestXXXXXXX\(fileExtension)"
    var templateBytes = template.utf8 + [0]
    let fd = templateBytes.withUnsafeMutableBufferPointer { ptr in
        ptr.baseAddress!.withMemoryRebound(to: Int8.self, capacity: ptr.count) { (ptr: UnsafeMutablePointer<Int8>) in
            return mkstemps(ptr, CInt(fileExtension.utf8.count))
        }
    }
    close(fd)
    templateBytes.removeLast()
    return String(decoding: templateBytes, as: UTF8.self)
}

internal func dumpToFile(data: Data, fileExtension: String = "") throws  -> String {
    let filename = makeTemporaryFile(fileExtension: fileExtension)
    try data.write(to: URL(fileURLWithPath: filename))
    return filename
}

internal func dumpToFile(text: String, fileExtension: String = "") throws -> String {
    return try dumpToFile(data: text.data(using: .utf8)!, fileExtension: fileExtension)
}
