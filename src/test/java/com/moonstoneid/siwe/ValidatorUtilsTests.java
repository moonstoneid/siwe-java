package com.moonstoneid.siwe;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import com.moonstoneid.siwe.util.ValidatorUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.web3j.crypto.Keys;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ValidatorUtilsTests {

    private static final String ADDRESS = "0x9D7e5B049f5dc02D2A3a744972978e77586520Df"; // Signing address
    private static final String ISSUED_AT = "2022-11-11T23:49:55.928Z";                 // ISO 8601 datetime string

    // --- Tests for validating ValidatorUtils ---

    @Test
    void testIsEIP55Address() {
        try (MockedStatic<Keys> keys = Mockito.mockStatic(Keys.class, Mockito.CALLS_REAL_METHODS)) {
            keys.when(() -> Keys.toChecksumAddress(ADDRESS)).thenReturn(ADDRESS);
            assertTrue(ValidatorUtils.isEIP55Address(ADDRESS), "Address validation failed");
        }
    }

    @Test
    void testIsEIP55AddressNegative() {
        String invalidEIP55Address = "0x9d7e5b049f5dc02d2a3a744972978e77586520df";
        try (MockedStatic<Keys> keys = Mockito.mockStatic(Keys.class, Mockito.CALLS_REAL_METHODS)) {
            keys.when(() -> Keys.toChecksumAddress(invalidEIP55Address)).thenReturn(ADDRESS);
            assertFalse(ValidatorUtils.isEIP55Address(invalidEIP55Address), "Address validation failed");
        }
    }

    @Test
    void testIsISO860Format() {
        try (MockedStatic<OffsetDateTime> odt = Mockito.mockStatic(OffsetDateTime.class, Mockito.CALLS_REAL_METHODS)) {

            // Returning null is sufficient, we just need to check that no DateTimeParseException is thrown
            odt.when(() -> OffsetDateTime.parse(ISSUED_AT)).thenReturn(null);
            assertTrue(ValidatorUtils.isISO860Format(ISSUED_AT), "ISO-860 datetime validation failed");
        }
    }

    @Test
    void testIsISO860FormatNegative() {
        String invalidISO860Date = "2022-11-11T25:49:55.928Z";
        try (MockedStatic<OffsetDateTime> odt = Mockito.mockStatic(OffsetDateTime.class, Mockito.CALLS_REAL_METHODS)) {

            odt.when(() -> OffsetDateTime.parse(invalidISO860Date)).thenThrow(DateTimeParseException.class);
            assertFalse(ValidatorUtils.isISO860Format(invalidISO860Date), "ISO-860 datetime validation failed");
        }
    }

}
