package com.axisbank.api.utils.security.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

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
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
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
     * @param privateKey
     * @param jweEncryptedPayload
     * @return
     * @throws ParseException
     * @throws JOSEException
     */
    private static String jweDecrypt(RSAPrivateKey privateKey, String jweEncryptedPayload)
            throws ParseException, JOSEException {

        JWEObject jwe = JWEObject.parse(jweEncryptedPayload);
        jwe.decrypt(new RSADecrypter(privateKey));
        String decryptedValue = jwe.getPayload().toString();
        return decryptedValue;
    }

    private static String jwSign(RSAPrivateKey privateKey, String payloadToSign) throws JOSEException {
        JWSSigner signer = new RSASSASigner(privateKey);
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(new Base64URL("kid")).build(),
                new Payload(payloadToSign));

        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    private static JWVerifyObject jwSignatureVerify(RSAPublicKey publicKey, String signedPayloadToVerify)
            throws JOSEException, ParseException {
        JWSObject jwsObject = JWSObject.parse(signedPayloadToVerify);
        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        boolean isSignatureValid = jwsObject.verify(verifier);
        JWVerifyObject jwverifyObject = new JWVerifyObject();
        jwverifyObject.setSignatureValid(isSignatureValid);
        if (isSignatureValid) {
            jwverifyObject.setPayloadAfterVerification(jwsObject.getPayload().toString());
        }
        return jwverifyObject;
    }

    public static String jweEncryptAndSign(RSAPublicKey publicKeyToEncrypt, RSAPrivateKey privateKeyToSign,
            String payloadToEncryptAndSign) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException,
            KeyStoreException, IOException, JOSEException {
        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
        EncryptionMethod enc = EncryptionMethod.A256GCM;
        String encryptedResult = jweEncrypt(alg, enc, publicKeyToEncrypt, payloadToEncryptAndSign);
        String signedResult = jwSign(privateKeyToSign, encryptedResult);
        return signedResult;
    }

    public static String jweVerifyAndDecrypt(RSAPublicKey publicKeyToVerify, RSAPrivateKey privateKeyToDecrypt,
            String payloadToVerifyAndDecrypt) throws JOSEException, ParseException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, KeyStoreException, IOException, UnrecoverableKeyException {

        JWVerifyObject jwVerifyObject = jwSignatureVerify(publicKeyToVerify, payloadToVerifyAndDecrypt);

        if (!jwVerifyObject.isSignatureValid()) {
            return null;
        } else {
            return jweDecrypt(privateKeyToDecrypt, jwVerifyObject.getPayloadAfterVerification());
        }
    }

    public static void main(String[] args) {
        // Replace the following placeholders with the actual private and public keys
        String privateKeyString = "-----BEGIN PRIVATE KEY-----\n"
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0\n"
                + "YsGyo27lufueO47Ba1Oa9zIMN3J57MLUf0dIcGLPYSMA290ktFkCrUdj0XJE3yPq\n"
                + "Ba2QHMsM83zbi02FQ+HcIRoCio0xeY1olV0FCQy3JcSjcqdJmuR8JMEX8Dt7p0vw\n"
                + "Nrt1n/2rDTEPkWpBjyWdc5eLSOKEW7r76V21Vy0aARBEV+RcpK+yXR7ZA/94m/bj\n"
                + "ZvcFxXYXajB4RJvWKrgwhSuQDvuu9oAyxIoy/XLKDUX6eWNAXjLoozR2PiXYNRNy\n"
                + "0eJ8bfSqv5FkcEmhoI83XvK9eM1P6wqXbJ+rn0FHNyM9aMmZj1dz7GOW7E6DU0Ep\n"
                + "ZCa3DE7tAgMBAAECggEAAgW2dLc8GNmDQhNqTAoJyJTZkFS7T9FkK51QIy3QYHV8\n"
                + "pgWDSEGa4Ol6l285mMHnsC4IMwaJaC1bsQMHTZ3oC8Zi+eMxWWaaMhoNLpqsGynX\n"
                + "MhNkzAFI54MX28sA9TcTEjXG7QwkbEyacbj556bcYtl8O1hCYNdzw4FsxtRpQpC6\n"
                + "K4ArsflG5JTqWqM7IvJdIR4aC7PiNHmMDpWf7gGQFaWnl7jN6bM23h2SN4nAJO55\n"
                + "iImHmdiAb25nnbdKc9omfs3ktTbs74Ka07AHtuMRdsF/6xbTiPYVQ7Tzh0lRDZve\n"
                + "xDteN9uZgtbe4YySIpaAfZdXkk7ouX+lkpbCY76RVwKBgQDMp/FIzRf4TiCgWPQv\n"
                + "tIZ0Cg6qTBuBs8xDGt5cFVZwn3PwMuV441uRaInx9p4ENiiP8kXAUNydMvf97x4E\n"
                + "l65yGtYRfe52HmOP4F3VAtp4v191c4oiRQj1uCOnC2nC1+1dmwygl7Ckqlw6QqWz\n"
                + "ML+KeXLjBYbmwf7bx8Wz4Q/lFwKBgQDwGOTqZzzYiHjWaTnlKJTX7wiCVy0dDn8N\n"
                + "o/KiHseYk63d4jw8hz7oALpoFmUJA8o+eZEW2/kPc40DyElTe8nDC5Jeb0VvbN+p\n"
                + "pobPxsWXDJIYYtAMYEGAvCOqhLMnyQb9ldBZ06zaXVDpMdXtYhZmD9rDPxkE/FNx\n"
                + "V9tCREx2mwKBgQDEF+sGcZWVEu8KFRGsIBJwXy6cGB6HEYsXhUgn/T383ZvOPEZJ\n"
                + "pbeYRQ1f7YiMyoPlISOaWSB581tRUet2RQweQv54diyluwp00mu17Wz+I4hI1rM1\n"
                + "kOY74vsuVK46xoCmnyjjO1VDAgUqwa9ZWc091o6xXhtbQeh8GBej+nMrcwKBgBZf\n"
                + "i31YT3AyD2iTd6SmCnCwwo86xmZtwmMoAuUejyTlpg8GFOzjAXanEre+Vn3nj4IQ\n"
                + "2/dQWj4ZW2udz09rOprlSidooQTIFXN+pBNah3ES585D7vUoRxJS9dPe977eWbtp\n"
                + "qXelZPcYOQDx9uhe+o1aLt2A1LkFNlVahYEAUku/AoGAa5HC1Xqa5RlWyDbvLyKj\n"
                + "IT2zNA2+3CCemJGpoy7W5vceBDHumc4fm2V1KsFllHVmZaVolKAyAzVVqp0/L4Ts\n"
                + "1BznLrYclqXFeIG5vUw77FlzKakSCrltfmZEgLbG49GZwajHruhwJTtrdU0/WwvH\n"
                + "rwT93M7Rh8W8gvuN497C+Tg=\n"
                + "-----END PRIVATE KEY-----";

        String publicKeyString = "-----BEGIN CERTIFICATE-----\n"
                + "MIIEZzCCAs+gAwIBAgIIRkJL3X2j2skwDQYJKoZIhvcNAQELBQAwcTELMAkGA1UE\n"
                + "BhMCSU4xCzAJBgNVBAgMAk1IMQ8wDQYDVQQHDAZNdW5iYWkxDTALBgNVBAoMBEF4\n"
                + "aXMxEjAQBgNVBAsMCUF4aXMgQmFuazEhMB8GA1UEAwwYcmd3Lmp3ZWp3cy51YXQu\n"
                + "YXhpc2IuY29tMB4XDTIzMDEwMzA1MzM0MloXDTI4MDEwMjA1MzM0MlowcTELMAkG\n"
                + "A1UEBhMCSU4xCzAJBgNVBAgMAk1IMQ8wDQYDVQQHDAZNdW5iYWkxDTALBgNVBAoM\n"
                + "BEF4aXMxEjAQBgNVBAsMCUF4aXMgQmFuazEhMB8GA1UEAwwYcmd3Lmp3ZWp3cy51\n"
                + "YXQuYXhpc2IuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQEALxNfMn7gVCJQgNxJ\n"
                + "2iwXnw41ZM8BZf/iwIKrMkeFZcnqnxSwTpGxKAaRy3ExkyGBVmJQuGIEIjCGJfqp\n"
                + "2SUNcr1UsFuy5kljiePR2TtjTZa4WwQ7RYFP9tk6u+0r7aVLk/jzfDx+ZHYjNjvy\n"
                + "6TpFkMJB0fASwboRHxlv0TDpO66E0cEpJpfrkI7MEZSf6DTam+qn4OFUiqspG2ooc\n"
                + "lf9l9hIg4QeRJegWhPJvcqSpAnasLyhHLpTfgZFetVDNwwCYqu4XEb2fyySOy/WgG\n"
                + "cz7fOU4mO1HxQ84TURjWhCbEmiAVHGY3y5Mc1tKgEupSvUGSSO2SlL9EXngunkv4\n"
                + "cLTw==\n"
                + "-----END CERTIFICATE-----";

        // Convert String keys to RSAPrivateKey and RSAPublicKey
        RSAPrivateKey privateKey = getPrivateKey(privateKeyString);
        RSAPublicKey publicKey = getPublicKey(publicKeyString);

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

    private static RSAPrivateKey getPrivateKey(String privateKeyString) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        privateKeyString = privateKeyString.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private static RSAPublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        publicKeyString = publicKeyString.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
