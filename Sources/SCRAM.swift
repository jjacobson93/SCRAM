import Foundation
import HMAC
import CryptoEssentials
import PBKDF2

final public class SCRAMClient<Variant: HashProtocol> {
    let gs2BindFlag = "n,,"
    
    public init() {
        
    }
    
    private func fixUsername(username: String) -> String {
        return replaceOccurrences(in: replaceOccurrences(in: username, where: "=", with: "=3D"), where: ",", with: "=2C")
    }
    
    private func parse(challenge: String) throws -> (nonce: String, salt: String, iterations: Int) {
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
    
    private func parse(finalResponse response: String) throws -> [UInt8] {
        var signature: [UInt8]? = nil
        
        for part in response.characters.split(separator: ",") where String(part).characters.count >= 3 {
            let part = String(part)
            
            if let first = part.characters.first {
                let data = part[part.startIndex.advanced(by: 2)..<part.endIndex]
                
                switch first {
                case "v":
                    signature = [UInt8](base64: data)
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
    
    public func authenticate(_ username: String, usingNonce nonce: String) throws -> String {
        return "\(gs2BindFlag)n=\(fixUsername(username: username)),r=\(nonce)"
    }
    
    public func process(_ challenge: String, with details: (username: String, password: [UInt8]), usingNonce nonce: String) throws -> (proof: String, serverSignature: [UInt8]) {
        guard let encodedHeader = [UInt8](gs2BindFlag.utf8).base64 else {
            throw SCRAMError.Base64Failure(original: [UInt8](gs2BindFlag.utf8))
        }
        
        let parsedResponse = try parse(challenge: challenge)

        let remoteNonce = parsedResponse.nonce
        
        guard String(remoteNonce[remoteNonce.startIndex..<remoteNonce.startIndex.advanced(by: 24)]) == nonce else {
            throw SCRAMError.InvalidNonce(nonce: parsedResponse.nonce)
        }
        
        let noProof = "c=\(encodedHeader),r=\(parsedResponse.nonce)"
        
        let salt = [UInt8](base64: parsedResponse.salt)
        let saltedPassword = try PBKDF2<Variant>.calculate(details.password, salt: salt, iterations: parsedResponse.iterations)
        
        let ck = [UInt8]("Client Key".utf8)
        let sk = [UInt8]("Server Key".utf8)
        
        let clientKey = HMAC<Variant>.authenticate(message: ck, withKey: saltedPassword)
        let serverKey = HMAC<Variant>.authenticate(message: sk, withKey: saltedPassword)

        let storedKey = Variant.calculate(clientKey)

        let authenticationMessage = "n=\(fixUsername(username: details.username)),r=\(nonce),\(challenge),\(noProof)"

        var authenticationMessageBytes = [UInt8
]()
        authenticationMessageBytes.append(contentsOf: authenticationMessage.utf8)
        
        let clientSignature = HMAC<Variant>.authenticate(message: authenticationMessageBytes, withKey: storedKey)
        let clientProof = xor(clientKey, clientSignature)
        let serverSignature = HMAC<Variant>.authenticate(message: authenticationMessageBytes, withKey: serverKey)
        
        guard let proof = clientProof.base64 else {
            throw SCRAMError.Base64Failure(original: clientProof)
        }

        return (proof: "\(noProof),p=\(proof)", serverSignature: serverSignature)
    }
    
    public func complete(fromResponse response: String, verifying signature: [UInt8]) throws -> String {
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
    case InvalidSignature(signature: [UInt8])
    case Base64Failure(original: [UInt8])
    case ChallengeParseError(challenge: String)
    case ResponseParseError(response: String)
    case InvalidNonce(nonce: String)
}