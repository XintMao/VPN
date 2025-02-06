import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    private final MessageDigest messageDigest;

    /*
     * Constructor -- initialise a digest for SHA-256
     */
    public HandshakeDigest() {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException n) {
            throw new RuntimeException("SHA-256 not found", n);
        }
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        if (input != null) {
            messageDigest.update(input);
        }
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return messageDigest.digest();
    }
}