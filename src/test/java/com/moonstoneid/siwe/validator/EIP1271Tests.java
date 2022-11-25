package com.moonstoneid.siwe.validator;

import com.moonstoneid.siwe.SiweMessage;
import com.moonstoneid.siwe.error.SiweException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EIP1271Tests {

    private static final String M1_MESSAGE = "example.com wants you to sign in with your Ethereum account:" +
            "\n0x9D7e5B049f5dc02D2A3a744972978e77586520Df\n\nSign in to use the app.\n\nURI: https://example.com" +
            "\nVersion: 1\nChain ID: 1\nNonce: AnX5ELrm2ap11uiNE0MR\nIssued At: 2022-11-11T23:49:55.928Z" +
            "\nExpiration Time: 2322-01-11T23:49:55.128Z\nNot Before: 2015-07-30T12:12:12.928Z" +
            "\nRequest ID: 260cbfd5-4d74-42fc\nResources:\n- https://example.com/my-web2-claim.json" +
            "\n- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/";
    private static final String M1_SIGNATURE = "0x437c6f6ec1eb544ced0a6fca44165af9f31e18e" +
            "95e2ec314361a58aeb008fa464ae449099994a5c76994a20b3fb8508e7ecc1e6b133c86dc42731de45fd69e781b";
    private static final String M1_SIGNATURE_INVALID_LENGTH = "0x437c6f6ec1eb";
    private static final String M1_SIGNATURE_INVALID_V = "0x437c6f6ec1eb544ced0a6fca44165af9f31e18e" +
            "95e2ec314361a58aeb008fa464ae449099994a5c76994a20b3fb8508e7ecc1e6b133c86dc42731de45fd69e000a";

    private static final String M2_MESSAGE = "127.0.0.1:8080 wants you to sign in with your Ethereum account:" +
            "\n0x9778f927127886106c6D11Ced2A1a59CbBC4D259\n\nSign in to use the app.\n\nURI: http://127.0.0.1:8080\n" +
            "Version: 1\nChain ID: 5\nNonce: IiFpdzBTnZOthb2xGENG\nIssued At: 2022-11-17T18:26:27.127849Z";
    private static final String M2_SIGNATURE = "0x";
    private static final String M2_SIGNATURE_INVALID = "0x123";

    // --- Tests for validating SignatureValidator ---

    @Test
    void testIsValidSignature() throws SiweException{
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M1_MESSAGE);
        String contractAddress = siweMsg.getAddress();
    }

}
