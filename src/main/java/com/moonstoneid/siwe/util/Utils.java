package com.moonstoneid.siwe.util;

import java.security.SecureRandom;

import org.apache.commons.lang3.RandomStringUtils;

public class Utils {

    private Utils() {

    }

    /**
     * Generates a secure nonce for use in the SiweMessage to prevent replay attacks.
     *
     * @return nonce with an alphanumeric char set
     */
    public static String generateNonce() {
        return RandomStringUtils.random(20, 0, 0, true, true, null, new SecureRandom());
    }

}
