import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    private static final int AES_KEY_LENGTH = 16; // AES-128
    private static final int IV_LENGTH = 16; // 16 bytes for AES CTR mode

    private byte[] ivbytes;
    private SessionKey key;
    private Cipher cipher;

    // Constructor to create a SessionCipher from a SessionKey. The IV is created automatically.
    public SessionCipher(SessionKey key) {
        if (key == null) {
            throw new IllegalArgumentException("SessionKey cannot be null.");
        }
        this.key = key;
        this.ivbytes = new byte[IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivbytes);
    }

    // Constructor to create a SessionCipher from a SessionKey and an IV.
    public SessionCipher(SessionKey key, byte[] ivbytes) {
        if (key == null || ivbytes == null) {
            throw new IllegalArgumentException("SessionKey and IV cannot be null.");
        }
        if (ivbytes.length != IV_LENGTH) {
            throw new IllegalArgumentException("IV must be " + IV_LENGTH + " bytes long.");
        }
        this.key = key;
        this.ivbytes = ivbytes.clone(); // Defensive copy
    }

    // Return the SessionKey
    public SessionKey getSessionKey() {
        return this.key;
    }

    // Return the IV as a byte array
    public byte[] getIVBytes() {
        return ivbytes.clone(); // Defensive copy
    }

    // Attach OutputStream to which encrypted data will be written.
    public CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(ivbytes);
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), ivSpec);
            return new CipherOutputStream(os, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to initialize Cipher: " + e.getMessage(), e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Invalid key or IV: " + e.getMessage(), e);
        }
    }

    // Attach InputStream from which decrypted data will be read.
    public CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(ivbytes);
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), ivSpec);
            return new CipherInputStream(inputstream, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to initialize Cipher: " + e.getMessage(), e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Invalid key or IV: " + e.getMessage(), e);
        }
    }
}
