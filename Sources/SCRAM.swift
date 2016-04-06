import Foundation
import HMAC
import CryptoEssentials
import PBKDF2
import C7
import SHA1

final public class SCRAMClient {
    static let gs2BindFlag = "n,,"
    let hashingMethod: HashProtocol.Type
    
    public init(hashingMethod: HashProtocol.Type) {
        self.hashingMethod = hashingMethod
    }
    
    private func fixUsername(username: String) -> String {
        return replaceOccurrences(in: replaceOccurrences(in: username, where: "=", with: "=3D"), where: ",", with: "=2C")
    }
    
    private func parse(challenge challenge: String) throws -> (nonce: String, salt: String, iterations: Int) {
        var nonce: String? = nil
        var iterations: Int? = nil
        var salt: String? = nil
        
        for part in challenge.characters.split(separator: ",") where String(part).characters.count >= 3 {
            let part = String(part)
            
            if let first = part.characters.first {
                let data = part[part.startIndex.advanced(by: 2)..<part.endIndex]
                
                switch first {
                case "r":
                    nonce = data
                case "i":
                    iterations = Int(data)
                case "s":
                    salt = data
                default:
                    break
                }
            }
        }
        
        if let nonce = nonce, iterations = iterations, salt = salt {
            return (nonce: nonce, salt: salt, iterations: iterations)
        }
        
        throw SCRAMError.ChallengeParseError(challenge: challenge)
    }
    
    private func parse(finalResponse response: String) throws -> [Byte] {
        var signature: [Byte]? = nil
        
        for part in response.characters.split(separator: ",") where String(part).characters.count >= 3 {
            let part = String(part)
            
            if let first = part.characters.first {
                let data = part[part.startIndex.advanced(by: 2)..<part.endIndex]
                
                switch first {
                case "v":
                    signature = [Byte](base64: data)
                default:
                    break
                }
            }
        }
        
        if let signature = signature {
            return signature
        }
        
        throw SCRAMError.ResponseParseError(response: response)
    }
    
    public func authenticate(username: String, usingNonce nonce: String) throws -> String {
        return "\(SCRAMClient.gs2BindFlag)n=\(fixUsername(username)),r=\(nonce)"
    }
    
    public func process(challenge challenge: String, with details: (username: String, password: [Byte]), usingNonce nonce: String) throws -> (proof: String, serverSignature: [Byte]) {
        guard let encodedHeader = [UInt8](SCRAMClient.gs2BindFlag.utf8).toBase64() else {
            throw SCRAMError.Base64Failure(original: [UInt8](SCRAMClient.gs2BindFlag.utf8))
        }
        
        let parsedResponse = try parse(challenge: challenge)

        let remoteNonce = parsedResponse.nonce
        
        guard String(remoteNonce[remoteNonce.startIndex..<remoteNonce.startIndex.advanced(by: 24)]) == nonce else {
            throw SCRAMError.InvalidNonce(nonce: parsedResponse.nonce)
        }
        
        let noProof = "c=\(encodedHeader),r=\(parsedResponse.nonce)"
        
        let salt = [Byte](base64: parsedResponse.salt)
        let saltedPassword = try PBKDF2.calculate(details.password, salt: salt, iterations: parsedResponse.iterations, variant: hashingMethod)
        
        let ck = [Byte]("Client Key".utf8)
        let sk = [Byte]("Server Key".utf8)
        
        let clientKey = HMAC.authenticate(ck, withKey: saltedPassword, using: hashingMethod)
        let serverKey = HMAC.authenticate(sk, withKey: saltedPassword, using: hashingMethod)

        let storedKey = hashingMethod.calculate(clientKey)

        let authenticationMessage = "n=\(fixUsername(details.username)),r=\(nonce),\(challenge),\(noProof)"

        var authenticationMessageBytes = [Byte]()
        authenticationMessageBytes.append(contentsOf: authenticationMessage.utf8)
        
        let clientSignature = HMAC.authenticate(authenticationMessageBytes, withKey: storedKey, using: hashingMethod)
        let clientProof = xor(clientKey, clientSignature)
        let serverSignature = HMAC.authenticate(authenticationMessageBytes, withKey: serverKey, using: hashingMethod)
        
        guard let proof = clientProof.toBase64() else {
            throw SCRAMError.Base64Failure(original: clientProof)
        }

        return (proof: "\(noProof),p=\(proof)", serverSignature: serverSignature)
    }
    
    public func complete(payload: String, forResponse response: String, verifying signature: [Byte]) throws -> String {
        let sig = try parse(finalResponse: response)

        if sig != signature {
            throw SCRAMError.InvalidSignature(signature: sig)
        }
        
        return ""
    }
}

/// Replaces occurrences of data with new data in a string
/// Because "having a single cross-platform API for a programming language is stupid"
/// TODO: Remove/update with the next Swift version
internal func replaceOccurrences(in string: String, where matching: String, with replacement: String) -> String {
    #if os(Linux)
        return string.stringByReplacingOccurrencesOfString(matching, withString: replacement)
    #else
        return string.replacingOccurrences(of: matching, with: replacement)
    #endif
}

public enum SCRAMError: ErrorProtocol {
    case InvalidSignature(signature: [Byte])
    case Base64Failure(original: [Byte])
    case ChallengeParseError(challenge: String)
    case ResponseParseError(response: String)
    case InvalidNonce(nonce: String)
}