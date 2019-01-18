package com.umantis.seniordev.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;

/**
 * HS256 algorithm.
 *
 * @author Gergely.Szakacs
 *
 */
public class Hs256JWTTokenHandler extends AbstractStandardJWTTokenHandler implements JWTTokenHandler {

    @Override
    public void init(final String secret) {
        try {
            this.verifier = new MACVerifier(new Base64(secret).decode());
            this.signer = new MACSigner(new Base64(secret).decode());
        } catch (JOSEException e) {
            throw new RuntimeException("Error initializing JWTTokenHandler", e);
        }
    }

}
