package com.moonstoneid.siwe.util;

import org.web3j.crypto.Keys;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

public class ValidatorUtils {

    private ValidatorUtils() {

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
     * Based on <a href="https://stackoverflow.com/a/64864796">this</a> Stack Overflow answer.
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
