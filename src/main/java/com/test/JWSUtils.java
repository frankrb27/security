package com.test;


import java.security.Signature;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;

/**
 * Atributo no repudio
 * @author frodriguez
 *
 */
public class JWSUtils {


	static Set<String> crit = new HashSet();
	
	
	public static void main(String[] args) throws Exception {
		crit.add("iat");crit.add("iss");crit.add("tan");
		JWSUtils.generateJWS1();
	}

	public static void generateJWS1() throws Exception {

		// Create payload
		String message = "Hello world!";

		Payload payload = new Payload(message);

		System.out.println("JWS payload message: " + message);

		// Create JWS header with HS256 algorithm
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
				.customParam("iat", System.currentTimeMillis())
				.customParam("iss", "C=UK, ST=England, L=London, O=Acme Ltd.")
				.customParam("tan", "cobiscorp.com")
				//.criticalParams(crit)
				.keyID("132").build();
		//header.co.setContentType("text/plain");

		System.out.println("JWS header: " + header.toJSONObject());

		// Create JWS object
		JWSObject jwsObject = new JWSObject(header, payload);

		SignedJWT signedJwt = null;
		
		// Create HMAC signer
		String sharedKey = "a0a2abd8-6162-41c3-83d6-1cf559b46afc";

		System.out.println("HMAC key: " + sharedKey);

		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
				.keyID("123")
				.generate();
		ECKey ecPublicJWK = ecJWK.toPublicJWK();

		// Create the EC signer
		JWSSigner signer = new ECDSASigner(ecJWK);
//		JWSSigner signer = new MACSigner(sharedKey.getBytes());

		try {
			jwsObject.sign(signer);
		}
		catch (JOSEException e) {
			System.out.println(signer.supportedJWSAlgorithms());
			System.err.println("Couldn't sign JWS object: " + e.getMessage());
			return;
		}

		// Serialise JWS object to compact format
		String s = jwsObject.serialize();

		System.out.println("Serialised JWS object: " + s);

		// Parse back and check signature

		try {
			jwsObject = JWSObject.parse(s);
			signedJwt = SignedJWT.parse(s);
		}
		catch (ParseException e) {
			System.err.println("Couldn't parse JWS object: " + e.getMessage());
			return;
		}

		System.out.println("JWS object successfully parsed");

		JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
//		JWSVerifier verifier = new MACVerifier(jwsObject.getSignature().decode());

		boolean verifiedSignature = false;

		try {
			System.out.println(jwsObject.getState());
			verifiedSignature = jwsObject.verify(verifier);
			System.out.println(jwsObject.getState());
		}
		catch (JOSEException e) {
			System.err.println("Couldn't verify signature: " + e.getMessage());
		}

		if (verifiedSignature) {
			System.out.println("Verified JWS signature!");
		}
		else {
			System.out.println("Bad JWS signature!");
			return;
		}

		System.out.println("Recovered payload message: " + jwsObject.getPayload());
	}


	public static void generateJWS() throws Exception {
		// Generate an EC key pair
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
				.keyID("123")
				.generate();
		ECKey ecPublicJWK = ecJWK.toPublicJWK();

		// Create the EC signer
		JWSSigner signer = new ECDSASigner(ecJWK);

		// Creates the JWS object with payload
		JWSObject jwsObject = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.ES256)
				.customParam("iat", System.currentTimeMillis())
				.customParam("iss", "C=UK, ST=England, L=London, O=Acme Ltd.")
				.customParam("tan", "cobiscorp.com")
				.criticalParams(crit)
				.keyID(ecJWK.getKeyID()).build(),
				new Payload("Elliptic cure"));

		// Compute the EC signature
		jwsObject.sign(signer);

		// Serialize the JWS to compact form
		String s = jwsObject.serialize();
		System.out.println(s);

		// The recipient creates a verifier with the public EC key
		JWSVerifier jwsVerifier = new ECDSAVerifier(ecPublicJWK);
		System.out.println(jwsVerifier);

		// Verify the EC signature
		System.out.println(jwsObject.verify(jwsVerifier));
		if (jwsObject.verify(jwsVerifier)) {
			System.out.println("ES256 signature verified");
		}
		if (jwsObject.getPayload().toString().equals("Elliptic cure")) {
			System.out.println(true);
		}
	}

	public static void jws () throws Exception {
		/***************************SENDER'S END ***********************************/

		JwtClaims claims = new JwtClaims();
		claims.setAudience("Admins");
		claims.setExpirationTimeMinutesInTheFuture(10); //10 minutes from now
		claims.setGeneratedJwtId();
		claims.setIssuer("CA");
		claims.setIssuedAtToNow();
		claims.setNotBeforeMinutesInThePast(2);
		claims.setSubject("100bytesAdmin");
		claims.setClaim("email", "<a href=\"mailto:100bytesAdmin@100bytes.com\">100bytesAdmin@100bytes.com</a>");
		claims.setClaim("Country", "Antartica");
		List hobbies = Arrays.asList("Blogging", "Playing cards", "Games");
		claims.setStringListClaim("hobbies", hobbies);
		System.out.println("Senders end :: " + claims.toJson());


		System.out.println(Signature.getInstance("SHA256withECDSA"));

		//SIGNING
		RsaJsonWebKey jsonSignKey = RsaJwkGenerator.generateJwk(2048);
		JsonWebSignature jws = new JsonWebSignature();
		jws.setKey(jsonSignKey.getPrivateKey());
		jws.setPayload(claims.toJson());
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		String signedJwt = jws.getCompactSerialization();
		System.out.println("Signed ::" + signedJwt);

		/***************************RECEIVER'S END ***********************************/

		JwtConsumer consumer = new JwtConsumerBuilder()
				.setExpectedAudience("Admins")
				.setExpectedIssuer("CA")
				.setVerificationKey(jsonSignKey.getPublicKey())
				.setRequireSubject()
				.build();
		JwtClaims receivedClaims = consumer.processToClaims(signedJwt);
		System.out.println("SUCESS :: JWT Validation :: " + receivedClaims.toJson());
	}
}