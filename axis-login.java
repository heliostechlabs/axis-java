import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.RequestBuilder;
import org.apache.hc.client5.http.classic.methods.StringRequestEntity;
import org.apache.hc.client5.http.classic.methods.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClientBuilder;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.net.URI;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class AxisBankAPIClient {
    private static final String AXIS_PUBLIC_KEY = "-----BEGIN CERTIFICATE-----\n" +
            "MIIERzCCAy+gAwIBAgIIRkJL3X2j2skwDQYJKoZIhvcNAQELBQAwcTELMAkGA1UE\n" +
            "BhMCSU4xCzAJBgNVBAgMAk1IMQ8wDQYDVQQHDAZNdW5iYWkxDTALBgNVBAoMBEF4\n" +
            "aXMxEjAQBgNVBAsMCUF4aXMgQmFuazEhMB8GA1UEAwwYcmd3Lmp3ZWp3cy51YXQu\n" +
            "YXhpc2IuY29tMB4XDTIzMDEwMzA1MzM0MloXDTI4MDEwMjA1MzM0MlowcTELMAkG\n" +
            "A1UEBhMCSU4xCzAJBgNVBAgMAk1IMQ8wDQYDVQQHDAZNdW5iYWkxDTALBgNVBAoM\n" +
            "BEF4aXMxEjAQBgNVBAsMCUF4aXMgQmFuazEhMB8GA1UEAwwYcmd3Lmp3ZWp3cy51\n" +
            "YXQuYXhpc2IuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnQp\n" +
            "Zr0a8kkIriT+rwwpAJ89IidiLfnII4/wW8gqgTXiijDkBCKuL1Unbw5Tu4c/KRPF\n" +
            "c7exhelePG+jPZtSTo5Kqy2IlosP4MOi4LFLNV4l8102nipumJ0KUAjnkGsalY2o\n" +
            "mIuae2uq6PI4gHhezCS0Q742qIbKI52tPw9ZTxeF8csPLn1dZPooJeK/3gWA3JS1\n" +
            "YTvqx1xANAKyy6eaXsrIBPZar/pypwNmfpbLk+smVxLem5gyG2Jmi56SOhQFXAVW\n" +
            "1NBbgeIEPsYlbghIFrzBXwzS8Hwcl2YMDl0UJsSzquAOcFhuDh6ZKqki6tgFN+KC\n" +
            "czeBCPDKsBVZtGdJVQIDAQABo4HiMIHfMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYE\n" +
            "FFAH79oC8dZ3Csggp0RdAL0QsLQJMIGiBgNVHSMEgZowgZeAFFAH79oC8dZ3Csgg\n" +
            "p0RdAL0QsLQJoXWkczBxMQswCQYDVQQGEwJJTjELMAkGA1UECAwCTUgxDzANBgNV\n" +
            "BAcMBk11bmJhaTENMAsGA1UECgwEQXhpczESMBAGA1UECwwJQXhpcyBCYW5rMSEw\n" +
            "HwYDVQQDDBhyZ3cuandlandzLnVhdC5heGlzYi5jb22CCEZCS919o9rJMAsGA1Ud\n" +
            "DwQEAwICvDANBgkqhkiG9w0BAQsFAAOCAQEALxNfMn7gVCJQgNxJ2iwXnw41ZM8B\n" +
            "Zf/iwIKrMkeFZcnqnxSwTpGxKAaRy3ExkyGBVmJQuGIEIjCGJfqp2SUNcr1UsFuy\n" +
            "5kljiePR2TtjTZa4WwQ7RYFP9tk6u+0r7aVLk/jzfDx+ZHYjNjvy6TpFkMJB0fAS\n" +
            "wboRHxlv0TDpO66E0cEpJpfrkI7MEZSf6DTam+qn4OFUiqspG2ooclf9l9hIg4Qe\n" +
            "RJegWhPJvcqSpAnasLyhHLpTfgZFetVDNwwCYqu4XEb2fyySOy/WgGcz7fOU4mO1\n" +
            "HxQ84TURjWhCbEmiAVHGY3y5Mc1tKgEupSvUGSSO2SlL9EXngunkv4cLTw==\n" +
            "-----END CERTIFICATE-----";

    private static final String PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0\n" +
            "YsGyo27lufueO47Ba1Oa9zIMN3J57MLUf0dIcGLPYSMA290ktFkCrUdj0XJE3yPq\n" +
            "Ba2QHMsM83zbi02FQ+HcIRoCio0xeY1olV0FCQy3JcSjcqdJmuR8JMEX8Dt7p0vw\n" +
            "Nrt1n/2rDTEPkWpBjyWdc5eLSOKEW7r76V21Vy0aARBEV+RcpK+yXR7ZA/94m/bj\n" +
            "ZvcFxXYXajB4RJvWKrgwhSuQDvuu9oAyxIoy/XLKDUX6eWNAXjLoozR2PiXYNRNy\n" +
            "0eJ8bfSqv5FkcEmhoI83XvK9eM1P6wqXbJ+rn0FHNyM9aMmZj1dz7GOW7E6DU0Ep\n" +
            "ZCa3DE7tAgMBAAECggEAAgW2dLc8GNmDQhNqTAoJyJTZkFS7T9FkK51QIy3QYHV8\n" +
            "pgWDSEGa4Ol6l285mMHnsC4IMwaJaC1bsQMHTZ3oC8Zi+eMxWWaaMhoNLpqsGynX\n" +
            "MhNkzAFI54MX28sA9TcTEjXG7QwkbEyacbj556bcYtl8O1hCYNdzw4FsxtRpQpC6\n" +
            "K4ArsflG5JTqWqM7IvJdIR4aC7PiNHmMDpWf7gGQFaWnl7jN6bM23h2SN4nAJO55\n" +
            "iImHmdiAb25nnbdKc9omfs3ktTbs74Ka07AHtuMRdsF/6xbTiPYVQ7Tzh0lRDZve\n" +
            "xDteN9uZgtbe4YySIpaAfZdXkk7ouX+lkpbCY76RVwKBgQDMp/FIzRf4TiCgWPQv\n" +
            "tIZ0Cg6qTBuBs8xDGt5cFVZwn3PwMuV441uRaInx9p4ENiiP8kXAUNydMvf97x4E\n" +
            "l65yGtYRfe52HmOP4F3VAtp4v191c4oiRQj1uCOnC2nC1+1dmwygl7Ckqlw6QqWz\n" +
            "ML+KeXLjBYbmwf7bx8Wz4Q/lFwKBgQDwGOTqZzzYiHjWaTnlKJTX7wiCVy0dDn8N\n" +
            "o/KiHseYk63d4jw8hz7oALpoFmUJA8o+eZEW2/kPc40DyElTe8nDC5Jeb0VvbN+p\n" +
            "pobPxsWXDJIYYtAMYEGAvCOqhLMnyQb9ldBZ06zaXVDpMdXtYhZmD9rDPxkE/FNx\n" +
            "V9tCREx2mwKBgQDEF+sGcZWVEu8KFRGsIBJwXy6cGB6HEYsXhUgn/T383ZvOPEZJ\n" +
            "pbeYRQ1f7YiMyoPlISOaWSB581tRUet2RQweQv54diyluwp00mu17Wz+I4hI1rM1\n" +
            "kOY74vsuVK46xoCmnyjjO1VDAgUqwa9ZWc091o6xXhtbQeh8GBej+nMrcwKBgBZf\n" +
            "i31YT3AyD2iTd6SmCnCwwo86xmZtwmMoAuUejyTlpg8GFOzjAXanEre+Vn3nj4IQ\n" +
            "2/dQWj4ZW2udz09rOprlSidooQTIFXN+pBNah3ES585D7vUoRxJS9dPe977eWbtp\n" +
            "qXelZPcYOQDx9uhe+o1aLt2A1LkFNlVahYEAUku/AoGAa5HC1Xqa5RlWyDbvLyKj\n" +
            "IT2zNA2+3CCemJGpoy7W5vceBDHumc4fm2V1KsFllHVmZaVolKAyAzVVqp0/L4Ts\n" +
            "1BznLrYclqXFeIG5vUw77FlzKakSCrltfmZEgLbG49GZwajHruhwJTtrdU0/WwvH\n" +
            "rwT93M7Rh8W8gvuN497C+Tg=\n" +
            "-----END PRIVATE KEY-----";

    private static final String API_URL = "https://sakshamuat.axisbank.co.in/gateway/api/v2/CRMNext/login";

    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            // Load public key
            RSAPublicKey axisPublicKey = loadPublicKey(AXIS_PUBLIC_KEY);

            // Load private key
            RSAPrivateKey privateKey = loadPrivateKey(PRIVATE_KEY_PEM);

            // Encode data and sign with private key
            String encodedToken = encodeAndSignData(privateKey, axisPublicKey);

            // Make HTTP request
            makeHttpRequest(encodedToken);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static RSAPublicKey loadPublicKey(String publicKeyPEM) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(publicKeyPEM))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return (RSAPublicKey) converter.getPublicKey((SubjectPublicKeyInfo) pemParser.readObject());
        }
    }

    private static RSAPrivateKey loadPrivateKey(String privateKeyPEM) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(privateKeyPEM))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) pemParser.readObject());
        }
    }

    private static String encodeAndSignData(RSAPrivateKey privateKey, RSAPublicKey publicKey) throws Exception {
        CipherParameters params = new ParametersWithRandom(new AsymmetricKeyParameter(true, privateKey), null);
        AsymmetricCipherKeyPair keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

        // Sign the data
        ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();
        try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(byteOutStream))) {
            writer.writeObject(keyPair);
        }

        // Base64 encode the signed data
        return Base64.getEncoder().encodeToString(byteOutStream.toByteArray());
    }

    private static void makeHttpRequest(String encodedToken) throws IOException, ParseException {
        try (CloseableHttpClient httpClient = CloseableHttpClientBuilder.create().build()) {
            HttpPost httpPost = new HttpPost(URI.create(API_URL));
            httpPost.setHeader("Content-Type", "application/jose+json");
            httpPost.setEntity(new StringRequestEntity(encodedToken, "application/jose+json"));

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                System.out.println("API Response: " + EntityUtils.toString(response.getEntity()));
            }
        }
    }
}
