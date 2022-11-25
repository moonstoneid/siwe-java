package com.moonstoneid.siwe.validator;

import com.moonstoneid.siwe.SiweMessage;
import com.moonstoneid.siwe.error.SiweException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
public class SignatureValidatorTests {

    private static final String EIP1271_MAGIC_VALUE = "0x1626ba7e";
    private static final String EIP1271_INCORRECT_MAGIC_VALUE = "0x11111111";

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

    @Mock
    protected EIP1271 eip1271;

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
    void testisValidSignatureContractWallet() throws SiweException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M2_MESSAGE);
        Web3j dummyWeb3j = Web3j.build(new HttpService(""));
        Mockito.when(eip1271.isValidSignature(any(),any())).thenReturn(
                new RemoteFunctionCall<>(null, () -> Numeric.hexStringToByteArray(EIP1271_MAGIC_VALUE)));

        try (MockedStatic<EIP1271> mock = Mockito.mockStatic(EIP1271.class, Mockito.CALLS_REAL_METHODS)) {
            mock.when(() -> EIP1271.load(any(), any(), (Credentials) any(), any())).thenReturn(eip1271);
            assertTrue(SignatureValidator.isValidSignature(siweMsg, M2_SIGNATURE, dummyWeb3j),
                    "Signature validation failed");
        }
    }

    @Test
    void testisValidSignatureContractWalletNegative() throws SiweException {
        SiweMessage siweMsg = new SiweMessage.Parser().parse(M2_MESSAGE);
        Web3j dummyWeb3j = Web3j.build(new HttpService(""));
        Mockito.when(eip1271.isValidSignature(any(),any())).thenReturn(
                new RemoteFunctionCall<>(null, () -> Numeric.hexStringToByteArray(EIP1271_INCORRECT_MAGIC_VALUE)));

        try (MockedStatic<EIP1271> mock = Mockito.mockStatic(EIP1271.class, Mockito.CALLS_REAL_METHODS)) {
            mock.when(() -> EIP1271.load(any(), any(), (Credentials) any(), any())).thenReturn(eip1271);
            assertFalse(SignatureValidator.isValidSignature(siweMsg, M2_SIGNATURE_INVALID, dummyWeb3j),
                    "Signature validation failed");
        }
    }

}
