import HMAC
import CryptoEssentials
import PBKDF2
import C7
import SHA1

final public class SCRAM {
    static let gs2BindFlag = "n,,"
    let hashingMethod: HashProtocol.Type
    
    init(hashingMethod: HashProtocol.Type) {
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
        guard let base64nonce = [UInt8](nonce.utf8).toBase64() else {
            throw SCRAMError.Base64Failure(original: [UInt8](nonce.utf8))
        }
        
        return "\(SCRAM.gs2BindFlag)n=\(fixUsername(username)),r=\(base64nonce)"
    }
    
    public func process(challenge challenge: String, with details: (username: String, password: [Byte]), usingNonce nonce: String) throws -> (proof: String, serverSignature: [Byte]) {
        guard let encodedHeader = [UInt8](SCRAM.gs2BindFlag.utf8).toBase64() else {
            throw SCRAMError.Base64Failure(original: [UInt8](SCRAM.gs2BindFlag.utf8))
        }
        
        let parsedResponse = try parse(challenge: challenge)

        let noProof = "c=\(encodedHeader),r=\(parsedResponse.nonce)"
        
        let salt = [Byte](base64: parsedResponse.salt)
        let saltedPassword = try PBKDF2.calculate(details.password, salt: salt, iterations: parsedResponse.iterations, variant: hashingMethod)

        var ck = [Byte](), sk = [Byte]()
        ck.append(contentsOf: "Client Key".utf8)

        sk.append(contentsOf: "Server Key".utf8)
        
        let clientKey = HMAC.authenticate(key: saltedPassword, message: ck, variant: hashingMethod)
        let serverKey = HMAC.authenticate(key: saltedPassword, message: sk, variant: hashingMethod)

        let hashingClientKey = hashingMethod.init(clientKey)
        let storedKey = hashingClientKey.calculate()

        let authenticationMessage = "n=\(fixUsername(details.username)),r=\(nonce),\(challenge),\(noProof)"

        var authenticationMessageBytes = [Byte]()
        authenticationMessageBytes.append(contentsOf: authenticationMessage.utf8)
        
        let clientSignature = HMAC.authenticate(key: storedKey, message: authenticationMessageBytes, variant: hashingMethod)
        let clientProof = xor(clientKey, clientSignature)
        let serverSignature = HMAC.authenticate(key: serverKey, message: authenticationMessageBytes, variant: hashingMethod)
        
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
}