package com.ba.auth;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;


@Service
public class TokenManager {

	Key key =Keys.secretKeyFor(SignatureAlgorithm.HS256);
	
	private static final int validity=5*60*1000;
	
	
	public String generateToken(String username){
	
		return Jwts.builder()
				.setSubject(username)
				.setIssuer("www.ibrahim.com")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+validity))
				.signWith(key)
				.compact();
	}
	public boolean tokenValidate(String token){
		if(getUsernameToken(token)!=null && isExpired(token)) {
			return true;
		}
		return false;
		
	}
	
	public String getUsernameToken(String token){
	Claims claims = getClaims(token);
	return claims.getSubject();
	}
	
	public boolean isExpired(String token){
		Claims claims = getClaims(token);
		return claims.getExpiration().after(new Date(System.currentTimeMillis()));
		}
	private Claims getClaims(String token) {
		
		return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
	}
}
