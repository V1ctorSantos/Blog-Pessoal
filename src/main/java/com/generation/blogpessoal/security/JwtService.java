package com.generation.blogpessoal.security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {
	
	public static final String SECRET = "f7b7326d743b8d6179ce817f0f6a92cea7efbc5b1cd7bd3c8a371850beda736d";
	
	//token ingrid@gmail.com 2024-06-04 9:40 assinatura
	
	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(getSignKey()).build()
				.parseClaimsJws(token).getBody();
	}
	//pega a assinatura extrida e trata ela para tornar ela entendivel
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	// recupera os dados da parte sub do claim onde encontramos o emial(usuario)
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	//data que o token expira
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	//valida se a data que o token expira esta dentro da validade ou seja, a data atual ainda não atingiu essa data
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	//validar se o usuario que foi extraido do token condiz com o usuario
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	// objetivo é calcular o tempo de validade do token, formar o claim com as onformações do token
	private String createToken(Map<String, Object> claims, String userName) {
		return Jwts.builder()
					.setClaims(claims)
					.setSubject(userName)
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
					.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}
	//gerar o token puxando os claims formados no metodo anterior
	public String generateToken(String userName) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName);
	}

}
