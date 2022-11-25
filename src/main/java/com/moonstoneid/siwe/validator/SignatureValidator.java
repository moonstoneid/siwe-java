package com.moonstoneid.siwe.validator;

import com.moonstoneid.siwe.SiweMessage;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SignatureValidator {

    // EIP-1271 magic value
    private static final String EIP1271_MAGIC_VALUE = "0x1626ba7e";
    private static final BigInteger GAS_LIMIT = BigInteger.valueOf(6721975L);
    private static final BigInteger GAS_PRICE = BigInteger.valueOf(20000000000L);
    private static Credentials credentials = null;

    static {
        try {
            credentials = Credentials.create(Keys.createEcKeyPair());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SignatureValidator() {

    }

    /**
     * Validates the signature for the given message.
     *
     * @param msg       The {@link SiweMessage}
     * @param sig       The signature for the given message
     * @param provider  Optional {@link Web3j} instance to check signature of smart contract wallets (EIP-1271)
     *
     * @return true if the signature is correct, else false
     */
    public static boolean isValidSignature(SiweMessage msg, String sig, Web3j provider) {
        return isEOAWalletSignature(msg, sig) || isContractWalletSignature(provider, msg, sig);
    }

    // Checks if signature was created with an Externally Owned Account (EOA)
    private static boolean isEOAWalletSignature(SiweMessage msg, String sig) {
        // Verify signature
        // Recover addresses from signature
        // Check if list contains value, ignore case-sensitivity
        List<String> addresses = isEOAWalletSignatureInternally(msg.toMessage(), sig);
        return addresses.stream().anyMatch(msg.getAddress()::equalsIgnoreCase);
    }

    // If the signature is correct, it returns a List<String> of addresses
    private static List<String> isEOAWalletSignatureInternally(String msg, String sig) {
        List<String> matchedAddresses = new ArrayList<>();
        byte[] msgHash = Sign.getEthereumMessageHash(msg.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Numeric.hexStringToByteArray(sig);

        // A valid signature must have a length of 65 bytes
        if(signatureBytes.length != 65){
            return matchedAddresses;
        }

        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }

        Sign.SignatureData sd = new Sign.SignatureData(v, Arrays.copyOfRange(signatureBytes, 0, 32),
                Arrays.copyOfRange(signatureBytes, 32, 64));

        // Iterate for each possible key to recover
        for (int i = 0; i < 4; i++) {
            BigInteger publicKey = null;
            try {
                publicKey = Sign.recoverFromSignature((byte) i, new ECDSASignature(
                        new BigInteger(1, sd.getR()), new BigInteger(1, sd.getS())), msgHash);
            } catch (Exception e){
                return matchedAddresses;
            }

            if (publicKey != null) {
                String addressRecovered = "0x" + Keys.getAddress(publicKey);
                matchedAddresses.add(addressRecovered);
            }
        }
        return matchedAddresses;
    }

    // Conducts an EIP-1271 signature check
    private static boolean isContractWalletSignature(Web3j provider, SiweMessage message, String signature) {
        // If provider is missing, EIP-1271 signature validation is skipped
        if(provider == null) {
            return false;
        }
        try {
            String contractAddress = message.getAddress();
            EIP1271 contract = EIP1271.load(contractAddress, provider, credentials, contractGasProvider);
            byte[] msgHash = Sign.getEthereumMessageHash(message.toMessage().getBytes(StandardCharsets.UTF_8));
            byte[] sig = Numeric.hexStringToByteArray(signature);

            byte[] response = contract.isValidSignature(msgHash, sig).sendAsync().get();
            if(response == null) {
                return false;
            }
            String responseAsHex = Numeric.toHexString(response);
            // Check if response matches EIP-1271 magic value
            return responseAsHex.equalsIgnoreCase(EIP1271_MAGIC_VALUE);
        } catch (Exception e) {
            return false;
        }
    }

    private static final ContractGasProvider contractGasProvider = new ContractGasProvider() {
        @Override
        public BigInteger getGasPrice(String contractFunc) {
            return GAS_PRICE;
        }

        @Override
        public BigInteger getGasPrice() {
            return GAS_PRICE;
        }

        @Override
        public BigInteger getGasLimit(String contractFunc) {
            return GAS_LIMIT;
        }

        @Override
        public BigInteger getGasLimit() {
            return GAS_LIMIT;
        }
    };

}