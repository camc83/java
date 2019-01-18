package com.umantis.seniordev.security.jwt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.umantis.seniordev.security.jwt.JWTTokenHandlerFactory.KnownAlgorithms;

public class Hs256JWTTokenHandlerTest {

    //    {
    //        "uname" : "userName",
    //        "uid" : "1001",
    //        "expires" : 1445508448227,
    //        "created" : 1445507448227,
    //        "roles" : ["MgmtUser","self","Restricted"],
    //    }

    static final String TEST_KEY =
            "9SyECk96oDsTmXfogIieDI0cD/8FpnojlYSUJT5U9I/FGVmBz5oskmjOR8cbXTvoPjX+Pq/T/b1PqpHX0lYm0oCBjXWICA==";

    private JWTTokenHandler tokenHandler;

    @Before
    public void setUp() throws JOSEException {
    	JWTTokenHandlerFactory factory = new JWTTokenHandlerFactory(TEST_KEY);
        this.tokenHandler = factory.createForAlgorithm(KnownAlgorithms.HS256);
    }

    @Test(expected = RuntimeException.class)
    public void testParseAuthToken1() throws JOSEException {
        JWTUserInfo userInfo = this.tokenHandler.parseAuthToken("*** random garbage ***");
        assertEquals("userName", userInfo.getUsername());
    }

    @Test
    public void testParseAuthToken2() throws JOSEException {
        JWSSigner signer = new MACSigner(new Base64(TEST_KEY).decode());
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        long now = System.currentTimeMillis();
        JWTClaimsSet claims = builder
        	    //    {
        	    //        "uname" : "userName",
        	    //        "uid" : "1001",
        	    //        "expires" : 1445508448227,
        	    //        "created" : 1445507448227,
        	    //        "roles" : ["MgmtUser","self","Restricted"],
        	    //    }
                .claim("uname", "userName")
                .claim("uid", "1001")
                .claim("expires", Long.valueOf(now + 1000000L))
                .claim("created", Long.valueOf(now))
                .claim("roles", Arrays.asList(new String[] { "MgmtUser", "self", "Restricted" }))
                .issueTime(new Date(now))
                .expirationTime(new Date(now + 1000000L))
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(signer);
        String token = signedJWT.serialize();
        JWTUserInfo userInfo = this.tokenHandler.parseAuthToken(token);
        assertEquals("userName", userInfo.getUsername());
        assertEquals("1001", userInfo.getUserId());
        assertEquals(now, userInfo.getCreated());
        assertTrue(userInfo.getRoles().contains("MgmtUser"));
    }

    @Test(expected = RuntimeException.class)
    public void testCreateAuthToken1() {
        this.tokenHandler.createAuthToken(new JWTUserInfo());
    }

    @SuppressWarnings("rawtypes")
    public void testCreateAuthToken2() throws JOSEException, ParseException {
	    //    {
	    //        "uname" : "userName",
	    //        "uid" : "1001",
	    //        "expires" : 1445508448227,
	    //        "created" : 1445507448227,
	    //        "roles" : ["MgmtUser","self","Restricted"],
	    //    }
    	
    	JWTUserInfo ui = new JWTUserInfo();
    	ui.setUserName("userName");
    	ui.setUserId("1001");
    	Set<String> roles = new HashSet<>();
    	roles.addAll(Arrays.asList(new String[]{"MgmtUser","self","Restricted"}));
    	ui.setRoles(roles);
        String token = this.tokenHandler.createAuthToken(ui);
        long now = System.currentTimeMillis();
        
        SignedJWT decodedSignedJWT = SignedJWT.parse(token);
        JWSVerifier verifier = new MACVerifier(new Base64(TEST_KEY).decode());
        assertTrue(decodedSignedJWT.verify(verifier));
        assertEquals("userName", decodedSignedJWT.getJWTClaimsSet().getClaim("uname"));
        assertEquals("1001", decodedSignedJWT.getJWTClaimsSet().getClaim("uid"));
        assertTrue(now + 1000L > decodedSignedJWT.getJWTClaimsSet().getLongClaim("created"));
        assertTrue(((Collection)decodedSignedJWT.getJWTClaimsSet().getClaim("roles")).contains("self"));
    }

}
