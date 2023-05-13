![siwe-java Logo](header.png "siwe-java Logo")

[![Build](https://github.com/moonstoneid/siwe-java/actions/workflows/build.yml/badge.svg)](https://github.com/moonstoneid/siwe-java/actions/workflows/build.yml)
[![Unit Tests](https://github.com/moonstoneid/siwe-java/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/moonstoneid/siwe-java/actions/workflows/unit-tests.yml)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.moonstoneid/siwe-java/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/com.moonstoneid/siwe-java?style=flat)
# Siwe-java

Siwe-java is a Java lib that implements Sign-In with Ethereum ([EIP-4361](https://eips.ethereum.org/EIPS/eip-4361)).

Sign-In with Ethereum (Siwe) defines how Ethereum accounts can authenticate with off-chain services by signing a
[standardized plaintext message](https://eips.ethereum.org/EIPS/eip-4361#example-message-to-be-signed).
Siwe-java provides methods to create a Siwe message from scratch, to parse existing Siwe strings and to validate its 
signature.

## Installation
Add the following Maven dependency to your project (requires Java 11 or higher).
```xml
<dependency>
    <groupId>com.moonstoneid</groupId>
    <artifactId>siwe-java</artifactId>
    <version>1.0.2</version>
</dependency>
```

## Usage
The following examples briefly show how to use siwe-java.

A full example can be found [here](example/src/main/java/com/moonstoneid/siwe/Example.java).

### Create new message
Create a new Siwe message from scratch and get a valid EIP-4361 string representation.
```java
try {
    // Create new SiweMessage
    SiweMessage siwe = new SiweMessage.Builder(domain, address, uri, version, chainId, nonce, issuedAt)
        .statement(statement).build();
    
    // Create EIP-4361 string from SiweMessage
    String msg = siwe.toMessage();     
} catch (SiweException e) {
    // Handle exception
}
 ```
### Parse existing message
Parse an EIP-4361 string into a Siwe message and verify its signature:
```java
String message = "example.com wants you to sign in with your Ethereum account:\n" +
    "0xAd472fbB6781BbBDfC4Efea378ed428083541748\n\n" +
    "Sign in to use the app.\n\n" +
    "URI: https://example.com\n" +
    "Version: 1\n" +
    "Chain ID: 1\n" +
    "Nonce: EnZ3CLrm6ap78uiNE0MU\n" +
    "Issued At: 2022-06-17T22:29:40.065529400+02:00";

String signature = "0x2ce1f57908b3d1cfece352a90cec9beab0452829a0bf741d26016d60676d63" +
        "807b5080b4cc387edbe741203387ef0b8a6e79743f636512cc48c80cbb12ffa8261b";
try {
    // Parse string to SiweMessage
    SiweMessage siwe = new SiweMessage.Parser().parse(message);

    // Verify integrity of SiweMessage by matching its signature
    siwe.verify("example.com", "EnZ3CLrm6ap78uiNE0MU", signature);
} catch (SiweException e) {
    // Handle exception
}
 ```

## Specification
The EIP-4361 specification can be found [here](https://eips.ethereum.org/EIPS/eip-4361).

## Contributing
Please use the [issue tracker](https://github.com/moonstoneid/siwe-java/issues) to report any bugs.

If you would like to contribute code, fork the repository and send a pull request. When submitting code, please make 
every effort to follow existing conventions and style in order to keep the code as readable as possible.

## Disclaimer 
This project has not undergone any formal security audit. Use at your own risk.

## Credits
Thanks to [@wyc](https://github.com/wyc) and [Spruce Systems, Inc.](https://github.com/spruceid) for pushing EIP-4361
forward.

## License
This project is distributed under the Apache License, Version 2.0 (see LICENSE file).

By submitting a pull request to this project, you agree to license your contribution under the Apache License, 
Version 2.0.