package com.umantis.seniordev.util;

import com.umantis.seniordev.security.jwt.JWTAuthenticationService;

/**
 * @author Marcin Szumski
 */
public class TestConstants {

    public static final String DOWNLOAD_ENDPOINT = "/download";
    public static final String UPLOAD_ENDPOINT = "/upload";
    public static final String AUTH_ENDPOINT = "/auth";

    public static final String AUTH_TOKEN_KEY = JWTAuthenticationService.JWT_HEADER_NAME;

    public static final String USERNAME_CERSEI = "cersei";
    public static final String PASS_CERSEI = "accessgranted";

    public static final String USERNAME_SANSA = "sansa";
    public static final String PASS_SANSA = "accessgranted1";

    public static final String USERNAME_WALDA = "walda";
    public static final String PASS_WALDA = "accessgranted3";

    public static final String USERNAME_YGRITTE = "ygritte";
    public static final String WRONG_PASS_YGRITTE = "accessdenied";

    public static final String UMANTIS_LOGO_PNG = "umantis_logo.png";
    public static final String APPLICATION_JSON_UTF8 = "application/json; charset=utf-8";

    public static final String HS256_SECRET = "9SyECk96oDsTmXfogIieDI0cD/8FpnojlYSUJT5U9I/FGVmBz5oskmjOR8cbXTvoPjX+Pq/T/b1PqpHX0lYm0oCBjXWICA==";

    public static final String UPLOAD_FILE_PARAM_NAME = "file";
    public static final String DOWNLOAD_FILE_ID_PARAM_NAME = "fileid";
    public static final String AUTH_PASS_PARAM_NAME = "p";
    public static final String AUTH_USERNAME_PARAM_NAME = "u";
}
