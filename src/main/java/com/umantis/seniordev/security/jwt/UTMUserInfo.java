package com.umantis.seniordev.security.jwt;

import java.util.Set;
import org.springframework.security.core.userdetails.UserDetails;

/**
 *
 * @author Gergely.Szakacs
 *
 */
interface UTMUserInfo extends UserDetails {

    String getUserName();

    String getUserId();

    Set<String> getRoles();

    long getCreated();

    long getExpires();
}
