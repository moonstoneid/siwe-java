package com.moonstone.siwe;

import com.moonstone.siwe.SiweMessage;
import com.moonstone.siwe.error.SiweException;

public class Example {

    public static final String domain = "example.com";                                  // Domain that requests signing
    public static final String address = "0xAd472fbB6781BbBDfC4Efea378ed428083541748";  // Signing address
    public static final String uri = "https://example.com";                             // Subject of the signing
    public static final String version = "1";                                           // Version of the message
    public static final int chainId = 1;                                                // EIP-155 Chain ID
    public static final String nonce = "EnZ3CLrm6ap78uiNE0MU";                          // Randomized token
    public static final String issuedAt = "2022-06-17T22:29:40.065529400+02:00";        // ISO 8601 datetime string
    public static final String statement = "Sign in to use the app.";                   // Assertion that the user signs

    // EIP-4361 string
    public static final String MESSAGE = "example.com wants you to sign in with your Ethereum account:\n" +
            "0xAd472fbB6781BbBDfC4Efea378ed428083541748\n\n" +
            "Sign in to use the app.\n\n" +
            "URI: https://example.com\n" +
            "Version: 1\n" +
            "Chain ID: 1\n" +
            "Nonce: EnZ3CLrm6ap78uiNE0MU\n" +
            "Issued At: 2022-06-17T22:29:40.065529400+02:00";

    // Matching signature
    public static final String SIGNATURE = "0x2ce1f57908b3d1cfece352a90cec9beab0452829a0bf741d26016d60676d" +
            "63807b5080b4cc387edbe741203387ef0b8a6e79743f636512cc48c80cbb12ffa8261b";

    public static void main(String[] args) {
        // Parse EIP-4361 string
        SiweMessage siweMessage = null;
        try {
            siweMessage = parseString(MESSAGE);
        } catch (SiweException e) {
            System.out.println("Parsing failed.");
        }

        // Verify signature
        if(siweMessage != null) {
            boolean isValid = verifySignature(siweMessage, "example.com", "EnZ3CLrm6ap78uiNE0MU",
                    SIGNATURE);
        }

        // Create new Siwe message from scratch
        try {
            SiweMessage newSiweMessage = createMessage();

            // Create EIP-4361 string
            String siweMessageAsString = newSiweMessage.toMessage();
        } catch (SiweException e) {
            System.out.println("Creation failed.");
        }
    }

    /**
     * Parses an EIP-4361 string.
     *
     * @return SiweMessage An object that holds the Siwe message
     * @throws SiweException if parsing fails
     */
    private static SiweMessage parseString(String message) throws SiweException{
        // Parse string into a Siwe message object
        SiweMessage siweMessage = new SiweMessage.Parser().parse(message);
        return siweMessage;
    }

    /**
     * Creates a new Siwe message from fields.
     *
     * @return SiweMessage An object that holds the Siwe message
     * @throws SiweException if mandatory fields are missing or in the wrong format
     */
    private static SiweMessage createMessage() throws SiweException{
        // Create new Siwe message
        SiweMessage siweMessage = new SiweMessage.Builder(domain, address, uri, version, chainId, nonce, issuedAt)
                .statement(statement).build();
        return siweMessage;
    }

    /**
     * Verifies the integrity of the fields of this object by checking several fields and the
     * validity of the signature.
     *
     * @param domain The domain that requests the signing
     * @param nonce The nonce that was issued to prevent replay attacks
     * @param signature A signature that matches the Siwe message
     *
     */
    private static boolean verifySignature(SiweMessage siweMessage, String domain, String nonce, String signature){
        // Verify integrity of the domain, the nonce and the signature
        try {
            siweMessage.verify(domain, nonce, signature);
            return true;
        } catch (SiweException e) {
            switch (e.getErrorType()) {
                case DOMAIN_MISMATCH:
                    System.out.println("Domain do not match provided domain for verification.");
                    break;
                case NONCE_MISMATCH:
                    System.out.println("Nonce do not match provided nonce for verification.");
                    break;
                case EXPIRED_MESSAGE:
                    System.out.println("Expired message.");
                    break;
                case NOT_YET_VALID_MESSAGE:
                    System.out.println("Message is not valid yet.");
                    break;
                case INVALID_SIGNATURE:
                    System.out.println("Invalid signature.");
                    break;
                default:
                    System.out.println("Unknown error.");
            }
            return false;
        }
    }

}