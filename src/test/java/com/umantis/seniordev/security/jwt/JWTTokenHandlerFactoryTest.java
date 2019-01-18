package com.umantis.seniordev.security.jwt;

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class JWTTokenHandlerFactoryTest {

    static final String TEST_KEY_HS256 = "9SyECk96oDsTmXfogIieDI0cD/8FpnojlYSUJT5U9I/FGVmBz5oskmjOR8cbXTvoPjX+Pq/T/b1PqpHX0lYm0oCBjXWICA==";
    static final String HS256_TOKEN =
            "eyJhbGciOiJIUzI1NiJ9.eyJ1bGFuZyI6ImVuIiwidWlkIjoiMTAwMSIsImV4cGlyZXMiOjE0NDU1MDg0NDgyMjcsImNsYW5nIjoiZW4iLCJjcmVhdGVkIjoxNDQ1NTA3NDQ4MjI3LCJuYW1lIjoidXNlck5hbWUiLCJleHAiOjE0NDczNDM0NzAsInR0bCI6MTAwMCwiaWF0IjoxNDQ3MzM5ODcwLCJkaWQiOiIxMDAyIiwiY2lkIjoiMTA2NyJ9.HfhAUoFD-oXLBxcXRDE_9x97Zc6fB-3ZEXr9ZdEwvHA";

    private JWTTokenHandlerFactory factory;

    @Before
    public void setUp() {
    }

    @Test
    public void testCreateForAlgorithmHs256() {
        this.factory = new JWTTokenHandlerFactory(TEST_KEY_HS256);
        JWTTokenHandler handler = this.factory.createForAlgorithm(JWTTokenHandlerFactory.KnownAlgorithms.HS256);
        assertTrue(handler instanceof Hs256JWTTokenHandler);
    }

    @Test
    public void createForToken() {
        this.factory = new JWTTokenHandlerFactory(TEST_KEY_HS256);
        JWTTokenHandler tokenHandler2 = this.factory.createForToken(HS256_TOKEN);
        assertTrue(tokenHandler2 instanceof Hs256JWTTokenHandler);
    }

}
