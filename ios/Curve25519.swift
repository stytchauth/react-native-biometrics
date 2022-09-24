import CryptoKit
import Foundation

@available(iOS 13, *)
@objc final class Curve25519: NSObject {
    @objc class func generateKeypair() -> Keypair {
        .init(privateKey: .init())
    }

    @objc class func signature(forPayload data: Data, privateKey: Data) throws -> Data {
        try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
            .signature(for: data)
    }

    @objc final class Keypair: NSObject {
        @objc let publicKey: Data
        @objc let privateKey: Data

        init(privateKey: CryptoKit.Curve25519.Signing.PrivateKey) {
            self.publicKey = privateKey.publicKey.rawRepresentation
            self.privateKey = privateKey.rawRepresentation
        }
    }
}
