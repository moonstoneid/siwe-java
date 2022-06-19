package org.mn.web3login;

import org.mn.web3login.siwe.SiweMessage;
import org.mn.web3login.siwe.error.SiweException;

public class Example {

    // A valid EIP-4361 formatted message
    public static final String MESSAGE = "localhost:8080 wants you to sign in with your Ethereum account:\n" +
            "0x76384DEC5e05C2487b58470d5F40c3aeD2807AcB\n\n" +
            "Sign in with Ethereum to the app" + ".\n\n" +
            "URI: http://localhost:8080\n" +
            "Version: 1\n" +
            "Chain ID: 1\n" +
            "Nonce: dqODS6hrQYe8CkhKj\n" +
            "Issued At: 2022-02-27T17:19:11.268Z\n" +
            "Expiration Time: 2024-02-27T17:19:11.268Z\n" +
            "Not Before: 2021-02-27T17:19:11.268Z\n" +
            "Request ID: abc\n" +
            "Resources:\n" +
            "- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/\n" +
            "- https://example.com/my-web2-claim.json";

    // A valid signature for Example.MESSAGE
    public static final String SIGNATURE =
            "0x2d079a5d5d9c0da3d97dd452f6b6eba0181f601eda26dd81df347ec70b2ca2d23a59a03f0071441b6fe35cc6658f36" +
                    "78b899d8e965efbaadba2149c7c6460c61B";

    public static void main(String[] args) {
        try {
            // Try to parse the String. Throws an exception if message is not a valid EIP-4361 message.
            SiweMessage siweMessage = new SiweMessage.Parser().parse(MESSAGE);

            // Validate signature. Throws an exception if signature is invalid, mandatory fields are missing,
            // expiration has been reached or now<notBefore
            siweMessage.verify("localhost:8080","dqODS6hrQYe8CkhKj", SIGNATURE);
        } catch (SiweException e) {
            e.printStackTrace();
        }
    }

}