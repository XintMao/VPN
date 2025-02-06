import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HandshakeCrypto {

    private X509Certificate cert;
    private PublicKey publickey = null;
    private PrivateKey privatekey = null;

    // Constructor for encryption/decryption with a public key (X509Certificate)
    public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
        cert = handshakeCertificate.getCertificate();
        if (cert == null) {
            throw new IllegalArgumentException("Provided HandshakeCertificate does not contain a valid certificate.");
        }
        publickey = cert.getPublicKey();
        if (publickey == null) {
            throw new IllegalStateException("Failed to extract public key from the provided certificate.");
        }
    }

    // Constructor for encryption/decryption with a private key (PKCS8/DER format)
    public HandshakeCrypto(byte[] keybytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (keybytes == null || keybytes.length == 0) {
            throw new IllegalArgumentException("Provided private key bytes are invalid (null or empty).");
        }
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            this.privatekey = factory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeySpecException("Failed to load private key. Ensure the key is in PKCS#8 format.", e);
        }
    }

    public static byte[] decrypt(byte[] sessionKeys, PrivateKey clientPrivateKey) {
        return sessionKeys;
    }

    // Decrypt method
    public byte[] decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty.");
        }
        Cipher cipher = Cipher.getInstance("RSA");
        if (privatekey != null) {
            cipher.init(Cipher.DECRYPT_MODE, privatekey);
        } else if (publickey != null) {
            cipher.init(Cipher.DECRYPT_MODE, publickey);
        } else {
            throw new IllegalStateException("Both public and private keys are null. Cannot perform decryption.");
        }
        return cipher.doFinal(ciphertext);
    }

    // Encrypt method
    public byte[] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty.");
        }
        Cipher cipher = Cipher.getInstance("RSA");
        if (publickey != null) {
            cipher.init(Cipher.ENCRYPT_MODE, publickey);
        } else if (privatekey != null) {
            cipher.init(Cipher.ENCRYPT_MODE, privatekey);
        } else {
            throw new IllegalStateException("Both public and private keys are null. Cannot perform encryption.");
        }
        return cipher.doFinal(plaintext);
    }
}
