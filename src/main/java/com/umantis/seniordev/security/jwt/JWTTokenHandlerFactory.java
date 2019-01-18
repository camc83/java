package com.umantis.seniordev.security.jwt;

import java.text.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;

/**
 * Factory class for creating a {@link JWTTokenHandler} instance with the configured secret key, based on the token format or algorithm.
 *
 * @author Gergely.Szakacs
 *
 */
@Service
public class JWTTokenHandlerFactory {

    /**
     * List of known encryption algorithms.
     *
     * @author Gergely.Szakacs
     *
     */
    public enum KnownAlgorithms {
        HS256
    }

    private static final String SEPARATOR_CHAR = "\\.";
    private static final Logger LOG = LoggerFactory.getLogger(JWTTokenHandlerFactory.class);

    private final String key;

    public JWTTokenHandlerFactory(final String key) {
        super();
        this.key = key;
    }

    /**
     * Creates a {@link JWTTokenHandler} instance for a given encryption algorithm.
     *
     * @param algorithm
     *            algorithm specified in application configuration
     * @return token handler implementation according to algorith, populated with the secret key
     * @throws IllegalArgumentException
     *             not handled algorithm
     */
    public JWTTokenHandler createForAlgorithm(final KnownAlgorithms algorithm) throws IllegalArgumentException {
        JWTTokenHandler tokenHandler = null;
        if (KnownAlgorithms.HS256.equals(algorithm)) {
            tokenHandler = new Hs256JWTTokenHandler();
        }
        tokenHandler.init(this.key);
        return tokenHandler;
    }

    /**
     * Creates a {@link JWTTokenHandler} instance for a token, based on the number of segments the token has.
     *
     * @param token
     *            Base64[URL] encoded token.
     * @return Hs256 if the token has two segments, Rs256 if the token has three segments
     * @throws IllegalArgumentException
     *             token has less than two segments and more than three
     */
    public JWTTokenHandler createForToken(final String token) throws IllegalArgumentException {
        if (!StringUtils.isEmpty(token)) {
            try {
                SignedJWT decodedSignedJWT = SignedJWT.parse(token);
                JWSHeader header = decodedSignedJWT.getHeader();
                JWTTokenHandler handler;
                switch (header.getAlgorithm().getName()) {
                    case "HS256":
                    case "Hs256":
                    case "hs256":
                        handler = new Hs256JWTTokenHandler();
                        handler.init(this.key);
                        return handler;
                    case "RS256":
                    case "Rs256":
                    case "rs256":
                    default:
                }
            } catch (ParseException e) {
                LOG.error("Error parsing token", e);
                throw new IllegalArgumentException("Error parsing token", e);
            }
        }
        LOG.error("Invalid token " + token);
        throw new IllegalArgumentException("Invalid token " + token);
    }
}
