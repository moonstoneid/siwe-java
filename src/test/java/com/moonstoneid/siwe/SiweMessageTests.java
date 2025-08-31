package com.moonstoneid.siwe;

import com.moonstoneid.siwe.error.ErrorTypes;
import com.moonstoneid.siwe.error.SiweException;
import com.moonstoneid.siwe.util.ValidatorUtils;
import com.moonstoneid.siwe.validator.SignatureValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.verification.VerificationMode;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;


class SiweMessageTests {
    private SiweMessage mSiweMsg;

    private static final String DOMAIN = "example.com";                                 // Domain that requests signing
    private static final String ADDRESS = "0x9D7e5B049f5dc02D2A3a744972978e77586520Df"; // Signing address
    private static final String URI = "https://example.com";                            // Subject of the signing
    private static final String VERSION = "1";                                          // Version of the message
    private static final int CHAIN_ID = 1;                                              // EIP-155 Chain ID
    private static final String NONCE = "AnX5ELrm2ap11uiNE0MR";                         // Randomized token
    private static final String ISSUED_AT = "2022-11-11T23:49:55.928Z";                 // ISO 8601 datetime string
    private static final String EXPIRATION_TIME = "2322-01-11T23:49:55.128Z";           // ISO 8601 datetime string
    private static final String NOT_BEFORE = "2015-07-30T12:12:12.928Z";                // ISO 8601 datetime string
    private static final String STATEMENT = "Sign in to use the app.";                  // Assertion that the user signs
    private static final String REQUEST_ID = "260cbfd5-4d74-42fc";                      // System-specific identifier
    private static final String[] RESOURCES = new String[]{
            "https://example.com/my-web2-claim.json",
            "ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/"};     // System-specific identifier

    private static final String SIGNATURE = "0x437c6f6ec1eb544ced0a6fca44165af9f31e18e" +
            "95e2ec314361a58aeb008fa464ae449099994a5c76994a20b3fb8508e7ecc1e6b133c86dc42731de45fd69e781b";

    private static final String MESSAGE_AS_STRING = "example.com wants you to sign in with your Ethereum account:" +
            "\n0x9D7e5B049f5dc02D2A3a744972978e77586520Df\n\nSign in to use the app.\n\nURI: https://example.com" +
            "\nVersion: 1\nChain ID: 1\nNonce: AnX5ELrm2ap11uiNE0MR\nIssued At: 2022-11-11T23:49:55.928Z" +
            "\nExpiration Time: 2322-01-11T23:49:55.128Z\nNot Before: 2015-07-30T12:12:12.928Z" +
            "\nRequest ID: 260cbfd5-4d74-42fc\nResources:\n- https://example.com/my-web2-claim.json" +
            "\n- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/";

    private static final String MESSAGE_AS_STRING_WITH_OPTIONAL_SCHEME = "https://example.com wants you to sign in with your Ethereum account:" +
            "\n0x9D7e5B049f5dc02D2A3a744972978e77586520Df\n\nSign in to use the app.\n\nURI: https://example.com" +
            "\nVersion: 1\nChain ID: 1\nNonce: AnX5ELrm2ap11uiNE0MR\nIssued At: 2022-11-11T23:49:55.928Z" +
            "\nExpiration Time: 2322-01-11T23:49:55.128Z\nNot Before: 2015-07-30T12:12:12.928Z" +
            "\nRequest ID: 260cbfd5-4d74-42fc\nResources:\n- https://example.com/my-web2-claim.json" +
            "\n- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/";

    // --- Tests for validating a new SiweMessage using the builder ---

    @Nested
    class BuilderValidationTests {

        @Test
        void testDomainValidationCorrect() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Domain validation failed");
        }

        @ParameterizedTest
        @NullAndEmptySource
        void testDomainValidationNegative(String domain) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(domain, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Domain validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_DOMAIN, "Incorrect exception error type!");
        }

        @Test
        void testAddressValidation() {
            assertDoesNotThrow(() -> {
                try (MockedStatic<ValidatorUtils> valUtil = Mockito.mockStatic(ValidatorUtils.class,
                        Mockito.CALLS_REAL_METHODS)) {
                    valUtil.when(() -> ValidatorUtils.isEIP55Address(ADDRESS)).thenReturn(true);

                    new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                            .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                            .requestId(REQUEST_ID).resources(RESOURCES).build();

                    valUtil.verify(() -> ValidatorUtils.isEIP55Address(ADDRESS), times(1));
                }
            }, "Address validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"0x28f4961f8b06f7361a1efd5e700de717b1db5292"}) // invalid EIP-55 address
        @NullAndEmptySource
        void testAddressValidationNegative(String address) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, address, URI, VERSION, CHAIN_ID,
                        NONCE, ISSUED_AT).statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Address validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_ADDRESS, "Incorrect exception error type!");
        }

        @Test
        void testStatementValidation() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement("I accept the Terms of Service: https://service.invalid/tos")
                        .expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE).requestId(REQUEST_ID)
                        .resources(RESOURCES).build();
            }, "Statement validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"I accept the Terms of Service\n"}) // invalid statement
        void testStatementValidationNegative(String statement) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID,
                        NONCE, ISSUED_AT).statement(statement).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Statement validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_STATEMENT, "Incorrect exception error type!");
        }

        @Test
        void testUriValidation() {
            assertDoesNotThrow(() -> {
                try (MockedStatic<ValidatorUtils> valUtil = Mockito.mockStatic(ValidatorUtils.class,
                        Mockito.CALLS_REAL_METHODS)) {
                    valUtil.when(() -> ValidatorUtils.isURI(URI)).thenReturn(true);

                    new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                            .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                            .requestId(REQUEST_ID).resources(RESOURCES).build();

                    valUtil.verify(() -> ValidatorUtils.isURI(URI), times(1));
                }
            }, "URI validation failed");
        }

        @ParameterizedTest
        @NullAndEmptySource
        void testUriValidationNegative(String uri) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                try (MockedStatic<ValidatorUtils> valUtil = Mockito.mockStatic(ValidatorUtils.class,
                        Mockito.CALLS_REAL_METHODS)) {
                    valUtil.when(() -> ValidatorUtils.isURI(uri)).thenReturn(false);

                    new SiweMessage.Builder(DOMAIN, ADDRESS, uri, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                            .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                            .requestId(REQUEST_ID).resources(RESOURCES).build();

                    valUtil.verify(() -> ValidatorUtils.isURI(URI));
                }
            }, "URI validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_URI, "Incorrect exception error type!");
        }

        @Test
        void testVersionValidation() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Version validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"2"}) // invalid version
        @NullAndEmptySource
        void testVersionValidationNegative(String version) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, version, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Version validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_MESSAGE_VERSION, "Incorrect exception error type!");
        }

        @Test
        void testNonceValidation() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Nonce validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"abcdefg"}) // invalid nonce
        @NullAndEmptySource
        void testNonceValidationNegative(String nonce) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, nonce, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Nonce validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_NONCE, "Incorrect exception error type!");
        }

        @Test
        void testIssuedAtValidation() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "IssuedAt validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"2022-11-11T25:49:55.928Z"}) // invalid ISO-8601 date string
        @NullAndEmptySource
        void testIssuedAtValidationNegative(String issuedAt) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, issuedAt)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "IssuedAt validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_TIME_FORMAT, "Incorrect exception error type!");
        }

        @Test
        void testExpirationTimeValidation() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "ExpirationTime validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"2022-11-11T25:49:55.928Z"}) // invalid ISO-8601 date string
        @EmptySource
        void testExpirationTimeValidationNegative(String expirationTime) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(expirationTime).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "ExpirationTime validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_TIME_FORMAT, "Incorrect exception error type!");
        }

        @Test
        void testNotBeforeValidation() {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "NotBefore validation failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"2022-11-11T25:49:55.928Z"}) // invalid ISO-8601 date string
        @EmptySource
        void testNotBeforeValidationNegative(String notBefore) {
            SiweException ex = assertThrows(SiweException.class, () -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(notBefore)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "NotBefore validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_TIME_FORMAT, "Incorrect exception error type!");
        }

        @Test
        void testResourcesValidation() throws SiweException {
            assertDoesNotThrow(() -> {
                new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                        .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                        .requestId(REQUEST_ID).resources(RESOURCES).build();
            }, "Resources validation failed");
        }

        @Test
        void testResourcesValidationNegative() {
            String[] resources = new String[]{"// this is an invalid url"};

            SiweException ex = assertThrows(SiweException.class, () -> {
                try (MockedStatic<ValidatorUtils> valUtil = Mockito.mockStatic(ValidatorUtils.class,
                        Mockito.CALLS_REAL_METHODS)) {
                    valUtil.when(() -> ValidatorUtils.isURI(resources[0])).thenReturn(false);

                    new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                            .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE)
                            .requestId(REQUEST_ID).resources(resources).build();

                    valUtil.verify(() -> ValidatorUtils.isURI(resources[0]));
                }
            }, "Resources validation failed");
            assertEquals(ex.getErrorType(), ErrorTypes.INVALID_RESOURCES, "Incorrect exception error type!");
        }

    }

    // --- Tests for creating a new SiweMessage using the builder ---

    @Nested
    class BuilderTests {

        @BeforeEach
        void setup() throws SiweException {
            mSiweMsg = new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                    .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE).requestId(REQUEST_ID)
                    .resources(RESOURCES).build();
        }

        @Test
        void testDomainCorrect() {
            assertEquals(DOMAIN, mSiweMsg.getDomain(), "Domain is incorrect!");
        }

        @Test
        void testAddressCorrect() {
            assertEquals(ADDRESS, mSiweMsg.getAddress(), "Address is incorrect!");
        }

        @Test
        void testURICorrect() {
            assertEquals(URI, mSiweMsg.getUri(), "URI is incorrect!");
        }

        @Test
        void testVersionCorrect() {
            assertEquals(VERSION, mSiweMsg.getVersion(), "Version is incorrect!");
        }

        @Test
        void testChainIdCorrect() {
            assertEquals(CHAIN_ID, mSiweMsg.getChainId(), "ChainId is incorrect!");
        }

        @Test
        void testNonceCorrect() {
            assertEquals(NONCE, mSiweMsg.getNonce(), "Nonce is incorrect!");
        }

        @Test
        void testIssuedAtCorrect() {
            assertEquals(ISSUED_AT, mSiweMsg.getIssuedAt(), "IssuedAt is incorrect!");
        }

        @Test
        void testStatementCorrect() {
            assertEquals(STATEMENT, mSiweMsg.getStatement(), "Statement is incorrect!");
        }

        @Test
        void testExpirationTimeCorrect() {
            assertEquals(EXPIRATION_TIME, mSiweMsg.getExpirationTime(), "ExpirationTime is incorrect!");
        }

        @Test
        void testNotBeforeCorrect() {
            assertEquals(NOT_BEFORE, mSiweMsg.getNotBefore(), "NotBefore is incorrect!");
        }

        @Test
        void testRequestIdCorrect() {
            assertEquals(REQUEST_ID, mSiweMsg.getRequestId(), "RequestId is incorrect!");
        }

        @Test
        void testResourcesCorrect() {
            assertEquals(RESOURCES, mSiweMsg.getResources(), "Resources is incorrect!");
        }

    }

    // --- Tests for creating a new SiweMessage using the parser ---

    @Nested
    class ParserTests {

        @BeforeEach
        void setup() throws SiweException {
            mSiweMsg = new SiweMessage.Parser().parse(MESSAGE_AS_STRING);
        }

        @Test
        void testInvalidMessage() {
            SiweException ex = assertThrows(SiweException.class, () -> new SiweMessage.Parser().parse("xyz"),
                    "Parsing failed!");
            assertEquals(ex.getErrorType(), ErrorTypes.UNABLE_TO_PARSE, "Incorrect exception error type!");
        }

        @Test
        void testOptionalScheme() {
            assertDoesNotThrow(() -> new SiweMessage.Parser().parse(MESSAGE_AS_STRING_WITH_OPTIONAL_SCHEME),
                    "Parsing optional scheme failed!"); // Tests fix for issue #3
        }

        @Test
        void testDomainCorrect() {
            assertEquals(DOMAIN, mSiweMsg.getDomain(), "Domain is incorrect!");
        }

        @Test
        void testAddressCorrect() {
            assertEquals(ADDRESS, mSiweMsg.getAddress(), "Address is incorrect!");
        }

        @Test
        void testURICorrect() {
            assertEquals(URI, mSiweMsg.getUri(), "URI is incorrect!");
        }

        @Test
        void testVersionCorrect() {
            assertEquals(VERSION, mSiweMsg.getVersion(), "Version is incorrect!");
        }

        @Test
        void testChainIdCorrect() {
            assertEquals(CHAIN_ID, mSiweMsg.getChainId(), "ChainId is incorrect!");
        }

        @Test
        void testNonceCorrect() {
            assertEquals(NONCE, mSiweMsg.getNonce(), "Nonce is incorrect!");
        }

        @Test
        void testIssuedAtCorrect() {
            assertEquals(ISSUED_AT, mSiweMsg.getIssuedAt(), "IssuedAt is incorrect!");
        }

        @Test
        void testStatementCorrect() {
            assertEquals(STATEMENT, mSiweMsg.getStatement(), "Statement is incorrect!");
        }

        @Test
        void testExpirationTimeCorrect() {
            assertEquals(EXPIRATION_TIME, mSiweMsg.getExpirationTime(), "ExpirationTime is incorrect!");
        }

        @Test
        void testNotBeforeCorrect() {
            assertEquals(NOT_BEFORE, mSiweMsg.getNotBefore(), "NotBefore is incorrect!");
        }

        @Test
        void testRequestIdCorrect() {
            assertEquals(REQUEST_ID, mSiweMsg.getRequestId(), "RequestId is incorrect!");
        }

        @Test
        void testResourcesCorrect() {
            assertArrayEquals(RESOURCES, mSiweMsg.getResources(), "Resources is incorrect!");
        }

    }

    // --- Tests for verifying a message ---

    @Nested
    class VerifyMessageTests {

        @BeforeEach
        void setup() throws SiweException {
            mSiweMsg = new SiweMessage.Parser().parse(MESSAGE_AS_STRING);
        }

        @Test
        void testVerifyMessageCorrect() {
            assertDoesNotThrow(() -> {
                mSiweMsg.verify(DOMAIN, NONCE, SIGNATURE);
            }, "Message verification failed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"https://google.com"}) // domain that does not match with domain in MESSAGE_AS_STRING
        @NullAndEmptySource
        void testDomainVerificationNegative(String domain) {
            SiweException ex = assertThrows(SiweException.class, () -> mSiweMsg.verify(domain, NONCE, SIGNATURE),
                    "Domain verification failed!");
            assertEquals(ex.getErrorType(), ErrorTypes.DOMAIN_MISMATCH, "Incorrect exception error type!");
        }

        @ParameterizedTest
        @ValueSource(strings = {"ABCDEFGHIJKL"}) // nonce that does not match with nonce in MESSAGE_AS_STRING
        @NullAndEmptySource
        void testNonceVerificationNegative(String nonce) {
            SiweException ex = assertThrows(SiweException.class, () -> mSiweMsg.verify(DOMAIN, nonce, SIGNATURE),
                    "Nonce verification failed!");
            assertEquals(ex.getErrorType(), ErrorTypes.NONCE_MISMATCH, "Incorrect exception error type!");
        }

        @ParameterizedTest
        @ValueSource(strings = {"0x437c6f6ec1eb1"}) // signature that does not match with signature in MESSAGE_AS_STRING
        @NullAndEmptySource
        void testSignatureVerificationNegative(String signature) {
            try (MockedStatic<SignatureValidator> sigVal = Mockito.mockStatic(SignatureValidator.class,
                    Mockito.CALLS_REAL_METHODS)) {
                sigVal.when(() -> SignatureValidator.isValidSignature(mSiweMsg, signature, null)).thenReturn(false);
                SiweException ex = assertThrows(SiweException.class, () -> mSiweMsg.verify(DOMAIN, NONCE, signature),
                        "Signature verification failed!");
                sigVal.verify(() -> SignatureValidator.isValidSignature(mSiweMsg, signature, null), atLeast(1));
                assertEquals(ex.getErrorType(), ErrorTypes.INVALID_SIGNATURE, "Incorrect exception error type!");
            }
        }

        @Test
        void testExpirationTimeVerificationNegative() {
            LocalDateTime fixedTime = LocalDateTime.of(2323, 1, 1, 12, 0);
            testWithMockedTime(fixedTime, ErrorTypes.EXPIRED_MESSAGE, "ExpiredAt verification failed!");
        }

        @Test
        void testNotBeforeVerificationNegative() {
            LocalDateTime fixedTime = LocalDateTime.of(2014, 1, 1, 12, 0);
            testWithMockedTime(fixedTime, ErrorTypes.NOT_YET_VALID_MESSAGE, "NotBefore verification failed!");
        }

        private void testWithMockedTime(LocalDateTime fixedTime, ErrorTypes expectedErrorType, String errorMsg) {
            Clock clock = Clock.fixed(fixedTime.toInstant(ZoneOffset.UTC), ZoneId.of("UTC"));
            OffsetDateTime fixedDateTime = OffsetDateTime.now(clock);

            try (MockedStatic<OffsetDateTime> offsetTime = Mockito.mockStatic(OffsetDateTime.class,
                    Mockito.CALLS_REAL_METHODS)) {
                offsetTime.when(() -> OffsetDateTime.now()).thenReturn(fixedDateTime);

                SiweException ex = assertThrows(SiweException.class, () -> mSiweMsg.verify(DOMAIN, NONCE, SIGNATURE),
                        errorMsg);
                offsetTime.verify(() -> OffsetDateTime.now(), atLeast(1));
                assertEquals(ex.getErrorType(), expectedErrorType, "Incorrect exception error type!");
            }
        }

    }

    // --- Tests for creating EIP-4361 string from SiweMessage ---

    @Nested
    class ToMessageTests {

        @BeforeEach
        void setup() throws SiweException {
            mSiweMsg = new SiweMessage.Builder(DOMAIN, ADDRESS, URI, VERSION, CHAIN_ID, NONCE, ISSUED_AT)
                    .statement(STATEMENT).expirationTime(EXPIRATION_TIME).notBefore(NOT_BEFORE).requestId(REQUEST_ID)
                    .resources(RESOURCES).build();
        }

        @Test
        void testToMessageCorrect() {
            assertEquals(MESSAGE_AS_STRING, mSiweMsg.toMessage(), "ToMessage is incorrect!");
        }

        @Test
        void testToMessageNegative() {
            assertNotEquals("Test", mSiweMsg.toMessage(), "ToMessage is incorrect!");
        }

    }

}