package com.umantis.seniordev.security.jwt;

/**
 * Interface for defining JWT token handler oprations.
 * 
 * @author Gergely.Szakacs
 *
 */
public interface JWTTokenHandler {

    /**
     * Sets the secret key and other parameters and initializes the tokenhandler.
     *
     * @param secret
     *            secret key in persisted format
     */
    void init(String secret);

    /**
     * Create auth token based on userinfo.
     *
     * @param userInfo
     *            User information
     * @return
     *         Create JWT token.
     */
    String createAuthToken(JWTUserInfo userInfo);

    /**
     * Parse JWT token to userinfo.
     *
     * @param token
     *            JWT token
     * @return
     *         Parsed information or if error occurs null value
     */
    JWTUserInfo parseAuthToken(String token);

}
