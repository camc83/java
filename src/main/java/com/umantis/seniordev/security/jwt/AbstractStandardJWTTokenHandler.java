package com.umantis.seniordev.security.jwt;

import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;

import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.umantis.seniordev.security.jwt.JWTUserInfo.JwtClaims;

/**
 * Common JWT operations.
 *
 * @author Gergely.Szakacs
 *
 */
public abstract class AbstractStandardJWTTokenHandler implements JWTTokenHandler {

    protected JWSVerifier verifier;
    protected JWSSigner signer;

    @Override
    public String createAuthToken(final JWTUserInfo userInfo) {
    	String token = null;
    	if (StringUtils.isEmpty(userInfo.getUserId()) || StringUtils.isEmpty(userInfo.getUserName())) {
    		throw new RuntimeException("Invalid userinfo");
    	} else {
        	try {
        		long now = System.currentTimeMillis();
    			JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    			JWTClaimsSet claims = builder
    			.claim(JwtClaims.USER_NAME, userInfo.getUserName())
    			.claim(JwtClaims.USER_ID, userInfo.getUserId())
    			.claim(JwtClaims.ROLES, userInfo.getRoles())
    			.claim(JwtClaims.CREATED, now)
    			.claim(JwtClaims.EXPIRES, now + 1000000L)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + 1000000L))
    			.build();
    			SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
    			signedJWT.sign(signer);
    			token = signedJWT.serialize();
    		} catch (JOSEException e) {
    			throw new RuntimeException("Error creating JWT token", e);
    		}
            return token;
    	}
    }

    @Override
    public JWTUserInfo parseAuthToken(final String token) {
        JWTUserInfo jwtUserInfo;
        try {
            SignedJWT decodedSignedJWT = SignedJWT.parse(token);
            JWTClaimsSet jwtClaimsSet = decodedSignedJWT.getJWTClaimsSet();
            if (decodedSignedJWT.verify(this.verifier)) {
                jwtUserInfo = new JWTUserInfo();
                jwtUserInfo.setUserName(jwtClaimsSet.getStringClaim(JwtClaims.USER_NAME));
                jwtUserInfo.setUserId(jwtClaimsSet.getStringClaim(JwtClaims.USER_ID));
                jwtUserInfo.setRoles(new HashSet<String>(jwtClaimsSet.getStringListClaim(JwtClaims.ROLES)));
                jwtUserInfo.setCreated(jwtClaimsSet.getLongClaim(JwtClaims.CREATED));
                jwtUserInfo.setExpires(jwtClaimsSet.getLongClaim(JwtClaims.EXPIRES));
                return jwtUserInfo;
            }
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Error parsing JWT token", e);
        }
        return null;
    }

}
