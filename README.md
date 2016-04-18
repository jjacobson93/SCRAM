# CryptoKitten

[![Build Status](https://travis-ci.org/CryptoKitten/SCRAM.svg?branch=master)](https://travis-ci.org/CryptoKitten/SCRAM)
[![Swift Version](https://img.shields.io/badge/swift-3.0-orange.svg)](https://swift.org)
![License](https://img.shields.io/github/license/CryptoKitten/SCRAM.svg)

A set of crypto libraries for Swift, written in Swift.
 
## MD5
 
SCRAM is a library that provides SCRAM authentication support on top of CryptoEssentials. Currently only supports the client SCRAM and is mainly used for MongoDB using SHA1. In the future we plan to support the server as well.

## Usage

```swift
// TODO: Please actually generate a random nonce. Don't hardcode it EVER
// let randomNonce = generateRandomNonce()
let randomNonce = "sadasd12u41enwsda"

let scram = SCRAM<SHA1>()

let clientFirst = scram.authenticate("Bob", usingNonce: randomNonce)

// TODO: Implement getServerFirst
// TODO: getServerFirst must send this message to the server appropriately
let serverResponse = getServerFirst(inReplyTo: clientFirst)

let passwordBytes = [UInt8]("hunter2".utf8)

// TODO: Don't crash...
let clientProof = try! scram.process(serverResponse, with: (username: "Bob", password: passwordBytes), usingNonce: randomNonce)

let reply = getServerFinal(inReplyTo: clientProof.proof)

// TODO: Check auth status yourself
while !checkAuthComplete() {
	// TODO: Don't crash.. you've got plenty to live for!
	// TODO: If the server signature is wrong this will throw. Handle that properly!
	let complete = try! scram.complete(fromResponse: serverFinalResponse, verifying: clientProof.serverSignature)
	
	// Complete should be an empty message.. otherwise an error should've been thrown
	reply = getServerFinal(inReplyTo: complete)
}

// TODO: Check if authentication is successful or unsuccessful
```

## License

**CryptoKitten uses parts of [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) whose license is included below.
Parts where CryptoSwift code is used have this license included in the file**

Copyright (C) 2014 Marcin Krzyżanowski marcin.krzyzanowski@gmail.com This software is provided 'as-is', without any express or implied warranty.

In no event will the authors be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:

    The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
    Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
    This notice may not be removed or altered from any source or binary distribution.
