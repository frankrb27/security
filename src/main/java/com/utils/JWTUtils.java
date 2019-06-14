package com.utils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Atributo Autenticidad
 * @author frodriguez
 *
 */
public class JWTUtils {

	// The secret key. This should be in a property file NOT under source
	// control and not hard coded in real life. We're putting it here for
	// simplicity.
	private static String SECRET_KEY = "oeRaYY7Wo24sDqKSX3IM9ASGmdGPmkTd9jo1QTy4b7P9Ze5_9hKolVX8xNrQDcNRfVEdTZNOuOyqEGhXEbdJI-ZQ19k_o9MI0y3eZN2lp9jow55FfXMiINEdt1XR85VipRLSOkT6kSpzs2x-jbLDiz9iFVzkd81YKxMgPA7VfZeQUm4n-mOmnWMaVX30zGFU4L3oPBctYKkl4dYfqYWqRNfrgPJVi5DGFjywgxx0ASEiJHtV72paI3fDR2XwlSkyhhmY-ICjCRmsJN4fX1pdoL8a18-aQrvyu4j0Os6dVPYIoPvvY0SAZtWYKHfM15g7A3HD4cVREf9cUsprCRK93w";

	//Sample method to construct a JWT
	public static String createJWT(String id, String issuer, String subject, long ttlMillis) {

		//The JWT signature algorithm we will be using to sign the token
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);

		//We will sign our JWT with our ApiKey secret
		byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
		Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

		//Headers
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("typ", "JWT");
		params.put("alg", "H256");
		
		//Let's set the JWT Claims
		JwtBuilder builder = Jwts.builder().setId(id)
				.setHeaderParams(params)
				.setIssuedAt(now)
				.setSubject(subject)
				.setIssuer(issuer)
				.claim("name", "Frank Rodriguez")
				.claim("role", "99")
				.signWith(signatureAlgorithm, signingKey);

		//if it has been specified, let's add the expiration
		if (ttlMillis >= 0) {
			long expMillis = nowMillis + ttlMillis;
			Date exp = new Date(expMillis);
			builder.setExpiration(exp);
		}

		//Builds the JWT and serializes it to a compact, URL-safe string
		return builder.compact();
	}

	public static Claims decodeJWT(String jwt) {

		//This line will throw an exception if it is not a signed JWS (as expected)
		Claims claims = Jwts.parser()
				.setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
				.parseClaimsJws(jwt).getBody();
		return claims;
	}
	
	public static void main (String ... strings) {
		String jwt = JWTUtils.createJWT("54", "COBIS", "open-api", 300000L);
		System.out.println(jwt);
		Claims claims = JWTUtils.decodeJWT(jwt);
		System.out.println(claims);
		//System.out.println(JWTUtils.decodeJWT("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI1NCIsImlhdCI6MTU2MDQzNzUwNCwic3ViIjoiQ09CSVMiLCJpc3MiOiJGcmFuayBSb2RyaWd1ZXoiLCJyb2xlIjoiOTkiLCJleHAiOjE1NjA0Mzc4MDR9.vrGt3ra4Es43a1GLXkwNZHM7Bpii2JsqZtOzZxnsSJY"));
	}
}
