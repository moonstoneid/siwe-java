package com.moonstoneid.siwe.validator;

import com.moonstoneid.siwe.SiweMessage;
import org.web3j.abi.DefaultFunctionEncoder;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bytes;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SignatureValidator {

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
     * @param msg      The {@link SiweMessage}
     * @param sig      The signature for the given message
     * @param provider Optional {@link Web3j} instance to check signature of smart contract wallets (EIP-6492)
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
        if (signatureBytes.length != 65) {
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
            } catch (Exception e) {
                return matchedAddresses;
            }

            if (publicKey != null) {
                String addressRecovered = "0x" + Keys.getAddress(publicKey);
                matchedAddresses.add(addressRecovered);
            }
        }
        return matchedAddresses;
    }

    // Conducts an EIP-6492 signature check
    private static boolean isContractWalletSignature(Web3j provider, SiweMessage message, String signature) {
        // If provider is missing, EIP-6492 signature validation is skipped
        if (provider == null) {
            return false;
        }
        try {
            String signerAddress = message.getAddress();
            String data = "%s%s".formatted(
                    EIP6492UniversalValidator.CODE,
                    DefaultFunctionEncoder.encodeConstructor(List.of(
                            new Address(signerAddress),
                            new Bytes32(Sign.getEthereumMessageHash(message.toMessage().getBytes(StandardCharsets.UTF_8))),
                            new DynamicBytes(Numeric.hexStringToByteArray(signature))
                    ))
            );
            EthCall result = provider
                    .ethCall(new Transaction(null, null, null, null, null, null, data), DefaultBlockParameterName.LATEST)
                    .send();

            if (result.hasError()) {
                return false;
            }

            return "0x01".equals(result.getValue());
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