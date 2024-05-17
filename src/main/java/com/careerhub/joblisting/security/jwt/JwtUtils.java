package com.careerhub.joblisting.security.jwt;


import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.careerhub.joblisting.security.service.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Component
public class JwtUtils {
	  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	  @Value("${careerhub.app.jwtSecret}")
	  private String jwtSecret;

	  @Value("${careerhub.app.jwtExpirationMs}")
	  private int jwtExpirationMs;

	  public String generateJwtToken(Authentication authentication) {

	    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

	    return Jwts.builder()
	        .subject((userPrincipal.getUsername()))
	        .issuedAt(new Date())
	        .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
	        .signWith(key())
	        .compact();
	  }
	  
	  private Key getSigningKey() {
		    byte[] keyBytes = Decoders.BASE64.decode(this.jwtSecret);
		    return Keys.hmacShaKeyFor(keyBytes);
		}
	  
	  private Key key() {
	    return getSigningKey();
	  }

	  public String getUserNameFromJwtToken(String token) {
	    return Jwts.parser().verifyWith((SecretKey)key()).build()
	               .parseSignedClaims(token).getPayload().getSubject();
	  }

	  public boolean validateJwtToken(String authToken) {
	    try {
	      Jwts.parser().verifyWith((SecretKey)key()).build().parse(authToken);
	      return true;
	    } catch (MalformedJwtException e) {
	      logger.error("Invalid JWT token: {}", e.getMessage());
	    } catch (ExpiredJwtException e) {
	      logger.error("JWT token is expired: {}", e.getMessage());
	    } catch (UnsupportedJwtException e) {
	      logger.error("JWT token is unsupported: {}", e.getMessage());
	    } catch (IllegalArgumentException e) {
	      logger.error("JWT claims string is empty: {}", e.getMessage());
	    }

	    return false;
	  }
}
