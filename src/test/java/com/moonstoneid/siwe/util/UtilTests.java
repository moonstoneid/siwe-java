package com.moonstoneid.siwe.util;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;

public class UtilTests {

    // --- Tests for validating Utils ---

    public static final String NONCE = "EnZ3CLrm6ap78uiNE0MU";                          // Randomized token

    @Test
    void testGenerateNonce() {
        try (MockedStatic<RandomStringUtils> random = Mockito.mockStatic(RandomStringUtils.class,
                Mockito.CALLS_REAL_METHODS)) {
            random.when(() -> RandomStringUtils.random(anyInt(), anyInt(), anyInt(), anyBoolean(), anyBoolean(), any(),
                    any())).thenReturn(NONCE);
            assertEquals(Utils.generateNonce(), NONCE);
            random.verify(() -> RandomStringUtils.random(eq(20), eq(0), eq(0), eq(true), eq(true), eq(null), any()),
                    atLeast(1));
        }
    }

}
