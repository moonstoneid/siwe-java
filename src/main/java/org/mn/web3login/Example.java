package org.mn.web3login;

import org.mn.web3login.siwe.SiweMessage;
import org.mn.web3login.siwe.error.SiweException;

public class Example {

    public static final String MESSAGE = "example.com wants you to sign in with your Ethereum account:\n" +
            "0xAd472fbB6781BbBDfC4Efea378ed428083541748\n\n" +
            "Sign in to use the app.\n\n" +
            "URI: https://example.com\n" +
            "Version: 1\n" +
            "Chain ID: 1\n" +
            "Nonce: EnZ3CLrm6ap78uiNE0MU\n" +
            "Issued At: 2022-06-17T22:29:40.065529400+02:00";

    public static final String SIGNATURE = "0x2ce1f57908b3d1cfece352a90cec9beab0452829a0bf741d26016d60676d" +
            "63807b5080b4cc387edbe741203387ef0b8a6e79743f636512cc48c80cbb12ffa8261b";

    public static void main(String[] args) {
        SiweMessage siweMessage;
        try {
            // Parse string to SiweMessage
            siweMessage = new SiweMessage.Parser().parse(MESSAGE);

            // Verify integrity of SiweMessage by matching its signature
            siweMessage.verify("example.com","EnZ3CLrm6ap78uiNE0MU", SIGNATURE);

        } catch (SiweException e) {
            // Handle exception
            e.printStackTrace();
        }
    }

}