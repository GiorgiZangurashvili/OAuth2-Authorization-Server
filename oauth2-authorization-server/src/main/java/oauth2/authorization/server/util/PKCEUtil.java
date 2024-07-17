package oauth2.authorization.server.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

public class PKCEUtil {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        var codeVerifier = generateCodeVerifier();
        var codeChallenge = generateCodeChallenge(codeVerifier);

        System.out.println(codeVerifier);
        System.out.println(codeChallenge);
    }

    public static String generateCodeVerifier() {
        // Generate a random string for code_verifier
        return Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes());
    }

    public static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        // Calculate SHA-256 hash of code_verifier
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes());

        // Encode hash as Base64 URL-encoded string without padding
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
