package org.mn.web3login.siwe.util;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.mn.web3login.siwe.SiweMessage;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

public class ValidatorUtils {

    // The EIP-191 prefix
    private static final String GETH_SIGN_PREFIX = "\u0019Ethereum Signed Message:\n";

    private ValidatorUtils() {

    }

    /**
     * Validates the signature for the given message.
     *
     * @param msg The {@link SiweMessage}
     * @param sig The signature for the given message
     *
     * @return true if the signature is correct, else false
     */
    public static boolean isValidSignature(SiweMessage msg, String sig) {
        return isAccountWalletSignature(msg, sig) || isContractWalletSignature(msg, sig);
    }

    private static boolean isAccountWalletSignature(SiweMessage msg, String sig) {
        // Verify signature
        // Recover addresses from signature
        // Check if list contains value, ignore case-sensitivity
        List<String> addresses = validateSignatureInternally(msg.toMessage(), sig);
        return addresses.stream().anyMatch(msg.getAddress()::equalsIgnoreCase);
    }

    private static boolean isContractWalletSignature(SiweMessage msg, String sig) {
        // TODO: Implement EIP-1271
        return false;
    }

    // If the signature is correct, it returns a List<String> of addresses
    private static List<String> validateSignatureInternally(String msg, String sig) {
        List<String> matchedAddresses = new ArrayList<>();
        String prefix = GETH_SIGN_PREFIX + msg.length();
        byte[] msgHash = Hash.sha3((prefix + msg).getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = Numeric.hexStringToByteArray(sig);
        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }

        Sign.SignatureData sd = new Sign.SignatureData(v, Arrays.copyOfRange(signatureBytes, 0, 32),
                Arrays.copyOfRange(signatureBytes, 32, 64));

        // Iterate for each possible key to recover
        for (int i = 0; i < 4; i++) {
            BigInteger publicKey = Sign.recoverFromSignature((byte) i, new ECDSASignature(
                    new BigInteger(1, sd.getR()), new BigInteger(1, sd.getS())), msgHash);

            if (publicKey != null) {
                String addressRecovered = "0x" + Keys.getAddress(publicKey);
                matchedAddresses.add(addressRecovered);
            }
        }
        return matchedAddresses;
    }

    /**
     * This method is supposed to check if an address is conforming to EIP-55.
     *
     * @param address Address to be checked if conforms with EIP-55
     *
     * @return true if address is in EIP-55 format, else false
     */
    public static boolean isEIP55Address(String address) {
        String checksumAddress = Keys.toChecksumAddress(address);
        return address.equals(checksumAddress);
    }

    /**
     * A naive check to ensure that a string is in ISO-860 date format.
     * Based on https://stackoverflow.com/a/64864796
     *
     * @param date The date as string
     *
     * @return true if the string is in ISO-860 format, else false
     */
    public static boolean isISO860Format(String date) {
        try {
            OffsetDateTime.parse(date);
        } catch (DateTimeParseException e) {
            return false;
        }
        return true;
    }

    /**
     * A naive check to ensure that a string is a valid URI.
     *
     * @param uri The URI as string
     *
     * @return true if the string is a valid URI, else false
     */
    public static boolean isURI(String uri) {
        try {
            URI u = new URI(uri);
        } catch (URISyntaxException e) {
            return false;
        }
        return true;
    }

}
