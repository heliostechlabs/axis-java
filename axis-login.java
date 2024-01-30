package com.axisbank.api.utils.security.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.management.RuntimeErrorException;

// import com.axisbank.api.utils.security.constants.JWEConstants;
// import com.axisbank.api.utils.security.pojo.JWVerifyObject;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;

public class JWEUtilsForPartners {

	
	/**
	 * 
	 * @param alg
	 * @param contentKeyEncMethod
	 * @param publicKey
	 * @param payload
	 * @return
	 * @throws JOSEException
	 */
	private static String jweEncrypt(JWEAlgorithm alg, EncryptionMethod contentKeyEncMethod, RSAPublicKey publicKey,
			String payload) throws JOSEException, NoSuchAlgorithmException {

		// Generate the preset Content Encryption (CEK) key
		KeyGenerator keyGenerator = KeyGenerator.getInstance('AES');
		keyGenerator.init(contentKeyEncMethod.cekBitLength());
		SecretKey cek = keyGenerator.generateKey();

		JWEHeader jewHeader = new JWEHeader(alg, contentKeyEncMethod);

		// Encrypt the JWE with the RSA public key + specified AES CEK
		JWEObject jwe = new JWEObject(jewHeader, new Payload(payload));
		jwe.encrypt(new RSAEncrypter(publicKey, cek));
		String jweString = jwe.serialize();
		return jweString;
	}

	/**
	 * 
	 * @param alg
	 * @param contentKeyEncMethod
	 * @param publicKey
	 * @param payload
	 * @return
	 * @throws JOSEException
	 * @throws ParseException
	 */
	private static String jweDecrypt(RSAPrivateKey privateKey, String jweEncryptedPayload)
			throws ParseException, JOSEException {

		JWEObject jwe = JWEObject.parse(jweEncryptedPayload);
		jwe.decrypt(new RSADecrypter(privateKey));
		String decryptedValue = jwe.getPayload().toString();
		return decryptedValue;
	}
	
	
	private static String jwSign(RSAPrivateKey privateKey, String payloadToSign) throws JOSEException {
		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(privateKey);
		// Prepare JWS object with simple string as payload
		JWSObject jwsObject = new JWSObject(
		    new JWSHeader(JWSAlgorithm.RS256),
		    new Payload(payloadToSign));

		// Compute the RSA signature
		jwsObject.sign(signer);
		
		// To serialize to compact form, produces something like
		// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
		// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
		// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
		// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
		return(jwsObject.serialize());
	}
	
	
	
	private static JWVerifyObject jwSignatureVerify(RSAPublicKey publicKey , String signedPayloadToVerify) throws JOSEException, ParseException {
		JWSObject jwsObject = JWSObject.parse(signedPayloadToVerify);
		JWSVerifier verifier = new RSASSAVerifier(publicKey);
	
		boolean isSignatureValid =  jwsObject.verify(verifier);
		JWVerifyObject jwverifyObject = new JWVerifyObject();
		jwverifyObject.setSignatureValid(isSignatureValid);
		if(isSignatureValid) {
			jwverifyObject.setPayloadAfterVerification(jwsObject.getPayload().toString());
		}
		return jwverifyObject;
	}

	
	

	
	
	public static String jweEncryptAndSign(RSAPublicKey publicKeyToEncrypt, RSAPrivateKey privateKeyToSign, String payloadToEncryptAndSign)
			throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, KeyStoreException,
			IOException, UnrecoverableKeyException, JOSEException {
		JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
		EncryptionMethod enc = EncryptionMethod.A256GCM;
		String encryptedResult = jweEncrypt(alg, enc, publicKeyToEncrypt, payloadToEncryptAndSign);
		String signedResult = jwSign(privateKeyToSign, encryptedResult);
		return signedResult;
	}
	
	
	public static String jweVerifyAndDecrypt(RSAPublicKey publicKeyToVerify, RSAPrivateKey privateKeyToDecrypt,  String payloadToVerifyAndDecrypt)
			throws JOSEException, ParseException, NoSuchAlgorithmException, CertificateException, FileNotFoundException,
			KeyStoreException, IOException, UnrecoverableKeyException {

		JWVerifyObject jwVerifyObject = jwSignatureVerify(publicKeyToVerify, payloadToVerifyAndDecrypt);

		if (!jwVerifyObject.isSignatureValid()) {
			// throw new RuntimeErrorException("Signature is not valid");
			return null;

		} else {
			return jweDecrypt(privateKeyToDecrypt, jwVerifyObject.getPayloadAfterVerification());
		}

	}
}


public static void main(String[] args) {
        // Replace the following placeholders with the actual private and public keys
        String privateKeyString = "-----BEGIN PRIVATE KEY-----
		MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0
		YsGyo27lufueO47Ba1Oa9zIMN3J57MLUf0dIcGLPYSMA290ktFkCrUdj0XJE3yPq
		Ba2QHMsM83zbi02FQ+HcIRoCio0xeY1olV0FCQy3JcSjcqdJmuR8JMEX8Dt7p0vw
		Nrt1n/2rDTEPkWpBjyWdc5eLSOKEW7r76V21Vy0aARBEV+RcpK+yXR7ZA/94m/bj
		ZvcFxXYXajB4RJvWKrgwhSuQDvuu9oAyxIoy/XLKDUX6eWNAXjLoozR2PiXYNRNy
		0eJ8bfSqv5FkcEmhoI83XvK9eM1P6wqXbJ+rn0FHNyM9aMmZj1dz7GOW7E6DU0Ep
		ZCa3DE7tAgMBAAECggEAAgW2dLc8GNmDQhNqTAoJyJTZkFS7T9FkK51QIy3QYHV8
		pgWDSEGa4Ol6l285mMHnsC4IMwaJaC1bsQMHTZ3oC8Zi+eMxWWaaMhoNLpqsGynX
		MhNkzAFI54MX28sA9TcTEjXG7QwkbEyacbj556bcYtl8O1hCYNdzw4FsxtRpQpC6
		K4ArsflG5JTqWqM7IvJdIR4aC7PiNHmMDpWf7gGQFaWnl7jN6bM23h2SN4nAJO55
		iImHmdiAb25nnbdKc9omfs3ktTbs74Ka07AHtuMRdsF/6xbTiPYVQ7Tzh0lRDZve
		xDteN9uZgtbe4YySIpaAfZdXkk7ouX+lkpbCY76RVwKBgQDMp/FIzRf4TiCgWPQv
		tIZ0Cg6qTBuBs8xDGt5cFVZwn3PwMuV441uRaInx9p4ENiiP8kXAUNydMvf97x4E
		l65yGtYRfe52HmOP4F3VAtp4v191c4oiRQj1uCOnC2nC1+1dmwygl7Ckqlw6QqWz
		ML+KeXLjBYbmwf7bx8Wz4Q/lFwKBgQDwGOTqZzzYiHjWaTnlKJTX7wiCVy0dDn8N
		o/KiHseYk63d4jw8hz7oALpoFmUJA8o+eZEW2/kPc40DyElTe8nDC5Jeb0VvbN+p
		pobPxsWXDJIYYtAMYEGAvCOqhLMnyQb9ldBZ06zaXVDpMdXtYhZmD9rDPxkE/FNx
		V9tCREx2mwKBgQDEF+sGcZWVEu8KFRGsIBJwXy6cGB6HEYsXhUgn/T383ZvOPEZJ
		pbeYRQ1f7YiMyoPlISOaWSB581tRUet2RQweQv54diyluwp00mu17Wz+I4hI1rM1
		kOY74vsuVK46xoCmnyjjO1VDAgUqwa9ZWc091o6xXhtbQeh8GBej+nMrcwKBgBZf
		i31YT3AyD2iTd6SmCnCwwo86xmZtwmMoAuUejyTlpg8GFOzjAXanEre+Vn3nj4IQ
		2/dQWj4ZW2udz09rOprlSidooQTIFXN+pBNah3ES585D7vUoRxJS9dPe977eWbtp
		qXelZPcYOQDx9uhe+o1aLt2A1LkFNlVahYEAUku/AoGAa5HC1Xqa5RlWyDbvLyKj
		IT2zNA2+3CCemJGpoy7W5vceBDHumc4fm2V1KsFllHVmZaVolKAyAzVVqp0/L4Ts
		1BznLrYclqXFeIG5vUw77FlzKakSCrltfmZEgLbG49GZwajHruhwJTtrdU0/WwvH
		rwT93M7Rh8W8gvuN497C+Tg=
		-----END PRIVATE KEY-----";

        String publicKeyString = "-----BEGIN CERTIFICATE-----
		MIIERzCCAy+gAwIBAgIIRkJL3X2j2skwDQYJKoZIhvcNAQELBQAwcTELMAkGA1UE
		BhMCSU4xCzAJBgNVBAgMAk1IMQ8wDQYDVQQHDAZNdW5iYWkxDTALBgNVBAoMBEF4
		aXMxEjAQBgNVBAsMCUF4aXMgQmFuazEhMB8GA1UEAwwYcmd3Lmp3ZWp3cy51YXQu
		YXhpc2IuY29tMB4XDTIzMDEwMzA1MzM0MloXDTI4MDEwMjA1MzM0MlowcTELMAkG
		A1UEBhMCSU4xCzAJBgNVBAgMAk1IMQ8wDQYDVQQHDAZNdW5iYWkxDTALBgNVBAoM
		BEF4aXMxEjAQBgNVBAsMCUF4aXMgQmFuazEhMB8GA1UEAwwYcmd3Lmp3ZWp3cy51
		YXQuYXhpc2IuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnQp
		Zr0a8kkIriT+rwwpAJ89IidiLfnII4/wW8gqgTXiijDkBCKuL1Unbw5Tu4c/KRPF
		c7exhelePG+jPZtSTo5Kqy2IlosP4MOi4LFLNV4l8102nipumJ0KUAjnkGsalY2o
		mIuae2uq6PI4gHhezCS0Q742qIbKI52tPw9ZTxeF8csPLn1dZPooJeK/3gWA3JS1
		YTvqx1xANAKyy6eaXsrIBPZar/pypwNmfpbLk+smVxLem5gyG2Jmi56SOhQFXAVW
		1NBbgeIEPsYlbghIFrzBXwzS8Hwcl2YMDl0UJsSzquAOcFhuDh6ZKqki6tgFN+KC
		czeBCPDKsBVZtGdJVQIDAQABo4HiMIHfMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYE
		FFAH79oC8dZ3Csggp0RdAL0QsLQJMIGiBgNVHSMEgZowgZeAFFAH79oC8dZ3Csgg
		p0RdAL0QsLQJoXWkczBxMQswCQYDVQQGEwJJTjELMAkGA1UECAwCTUgxDzANBgNV
		BAcMBk11bmJhaTENMAsGA1UECgwEQXhpczESMBAGA1UECwwJQXhpcyBCYW5rMSEw
		HwYDVQQDDBhyZ3cuandlandzLnVhdC5heGlzYi5jb22CCEZCS919o9rJMAsGA1Ud
		DwQEAwICvDANBgkqhkiG9w0BAQsFAAOCAQEALxNfMn7gVCJQgNxJ2iwXnw41ZM8B
		Zf/iwIKrMkeFZcnqnxSwTpGxKAaRy3ExkyGBVmJQuGIEIjCGJfqp2SUNcr1UsFuy
		5kljiePR2TtjTZa4WwQ7RYFP9tk6u+0r7aVLk/jzfDx+ZHYjNjvy6TpFkMJB0fAS
		wboRHxlv0TDpO66E0cEpJpfrkI7MEZSf6DTam+qn4OFUiqspG2ooclf9l9hIg4Qe
		RJegWhPJvcqSpAnasLyhHLpTfgZFetVDNwwCYqu4XEb2fyySOy/WgGcz7fOU4mO1
		HxQ84TURjWhCbEmiAVHGY3y5Mc1tKgEupSvUGSSO2SlL9EXngunkv4cLTw==
		-----END CERTIFICATE-----";

        // Convert String keys to RSAPrivateKey and RSAPublicKey
        RSAPrivateKey privateKey = /* Convert privateKeyString to RSAPrivateKey */;
        RSAPublicKey publicKey = /* Convert publicKeyString to RSAPublicKey */;

        // Example usage
        try {
            String payload = "alwebuser";
            String encryptedAndSigned = jweEncryptAndSign(publicKey, privateKey, payload);
            System.out.println("Encrypted and Signed: " + encryptedAndSigned);

            String decryptedAndVerified = jweVerifyAndDecrypt(publicKey, privateKey, encryptedAndSigned);
            System.out.println("Decrypted and Verified: " + decryptedAndVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
}
