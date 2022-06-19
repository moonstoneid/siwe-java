package org.mn.web3login.siwe.error;

public enum ErrorTypes {

    /**
     * Thrown when the `expirationTime` is present and in the past.
     */
    EXPIRED_MESSAGE(-1, "Expired message."),

    /**
     * Thrown when the `domain` is empty.
     */
    INVALID_DOMAIN(-2, "Invalid domain."),

    /**
     * Thrown when `domain` doesn't match the domain provided for verification.
     */
    DOMAIN_MISMATCH(-3, "Domain do not match provided domain for verification."),

    /**
     * Thrown when `nonce` doesn't match the nonce provided for verification.
     */
    NONCE_MISMATCH(-4, "Nonce do not match provided nonce for verification."),

    /**
     * Thrown when `address` does not conform to EIP-55 or is not a valid address.
     */
    INVALID_ADDRESS(-5, "Invalid address."),

    /**
     * Thrown when `uri` does not conform to RFC 3986.
     */
    INVALID_URI(-6, "URI does not conform to RFC 3986.."),

    /**
     * Thrown when `nonce` is smaller than 8 characters or is not alphanumeric.
     */
    INVALID_NONCE(-7, "Nonce size smaller then 8 characters or is not alphanumeric."),

    /**
     * Thrown when the `notBefore` is present and in the future.
     */
    NOT_YET_VALID_MESSAGE(-8, "Message is not valid yet."),

    /**
     * Thrown when signature doesn't match the address of the message.
     */
    INVALID_SIGNATURE(-9, "Signature do not match address of the message."),

    /**
     * Thrown when `expirationTime`, `notBefore` or `issuedAt` not complient to ISO-8601.
     */
    INVALID_TIME_FORMAT(-10, "Invalid time format."),

    /**
     * Thrown when `version` is not 1.
     */
    INVALID_MESSAGE_VERSION(-11, "Invalid message version."),

    /**
     * Thrown when `statement` is null.
     */
    INVALID_STATEMENT(-12, "Invalid statement."),

    /**
     * Thrown when `resources` contains invalid URIs.
     */
    INVALID_RESOURCES(-13, "Invalid URI in resources."),

    /**
     * Thrown when some required field is missing.
     */
    UNABLE_TO_PARSE(-14, "Unable to parse the message.");

    private final int number;
    private final String text;

    /**
     * Constructs a new enumeration constant with the provided error number and message.
     *
     * @param number The error number.
     * @param text   The error message.
     */
    ErrorTypes(int number, String text) {
        this.number = number;
        this.text = text;
    }

}
