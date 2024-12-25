package com.moonstoneid.siwe.validator;

import com.moonstoneid.siwe.SiweMessage;
import com.moonstoneid.siwe.error.SiweException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.core.methods.response.EthCall;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SignatureValidatorTests {
    private static final String EIP6492_CONTRACT_SUCCESS = "0x01";
    private static final String EIP6492_CONTRACT_FAILURE = "0x00";

    // EOA wallet messages & signature
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

    // Contract wallet message & signature
    private static final String M2_MESSAGE = "127.0.0.1:8080 wants you to sign in with your Ethereum account:" +
            "\n0x9778f927127886106c6D11Ced2A1a59CbBC4D259\n\nSign in to use the app.\n\nURI: http://127.0.0.1:8080\n" +
            "Version: 1\nChain ID: 5\nNonce: IiFpdzBTnZOthb2xGENG\nIssued At: 2022-11-17T18:26:27.127849Z";
    private static final String M2_SIGNATURE = "0x";
    private static final String M2_SIGNATURE_INVALID = "0x123";

    // --- Tests for validating SignatureValidator ---

    @Test
    void testisValidSignatureEOA() throws SiweException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M1_MESSAGE);
        assertTrue(SignatureValidator.isValidSignature(siweMsg, M1_SIGNATURE, null), "Signature validation failed");
    }

    @Test
    void testisValidSignatureEOASignatureLengthNegative() throws SiweException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M1_MESSAGE);
        assertFalse(SignatureValidator.isValidSignature(siweMsg, M1_SIGNATURE_INVALID_LENGTH, null),
                "Signature validation failed");
    }

    @Test
    void testisValidSignatureEOASignatureVNegative() throws SiweException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M1_MESSAGE);
        assertFalse(SignatureValidator.isValidSignature(siweMsg, M1_SIGNATURE_INVALID_V, null),
                "Signature validation failed");
    }

    @Test
    void testisValidSignatureContractWallet() throws SiweException, IOException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M2_MESSAGE);

        EthCall ethCall = new EthCall();
        ethCall.setResult(EIP6492_CONTRACT_SUCCESS);
        Web3j web3j = web3jWithEthCallResult(ethCall);

        assertTrue(SignatureValidator.isValidSignature(siweMsg, M2_SIGNATURE, web3j),
                "Signature validation failed");
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Web3j web3jWithEthCallResult(EthCall ethCall) throws IOException {
        Request<?, EthCall> request = mock(Request.class);
        when(request.send()).thenReturn(ethCall);
        Web3j web3j = mock(Web3j.class);
        when(web3j.ethCall(any(), any())).thenReturn((Request) request);
        return web3j;
    }

    @Test
    void testisValidSignatureContractWalletNegative() throws SiweException, IOException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M2_MESSAGE);
        EthCall ethCall = new EthCall();
        ethCall.setResult(EIP6492_CONTRACT_FAILURE);
        Web3j web3j = web3jWithEthCallResult(ethCall);
        assertFalse(SignatureValidator.isValidSignature(siweMsg, M2_SIGNATURE_INVALID, web3j),
                "Signature validation failed");
    }

    @Test
    void testisValidSignatureContractWalletError() throws SiweException, IOException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M2_MESSAGE);
        EthCall ethCall = new EthCall();
        ethCall.setError(new Response.Error(1234, "test error"));
        Web3j web3j = web3jWithEthCallResult(ethCall);
        assertFalse(SignatureValidator.isValidSignature(siweMsg, M2_SIGNATURE_INVALID, web3j),
                "Signature validation failed");
    }
}
