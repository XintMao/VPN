import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    private SecretKey secretKey;
    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) {
        try {
            // 检查密钥长度是否为AES支持的值（128, 192或256位）
            if (length != 128 && length != 192 && length != 256) {
                throw new IllegalArgumentException("无效的密钥长度。AES密钥长度必须是128、192或256位。");
            }
            // 使用 KeyGenerator 生成指定长度的 AES 密钥
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(length); // 初始化生成器，设置密钥长度
            this.secretKey = keyGen.generateKey(); // 生成密钥并保存
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public SessionKey(byte[] keybytes) {
            this.secretKey = new SecretKeySpec(keybytes, "AES");
        }
    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */


    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
       // return null;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return this.secretKey.getEncoded(); // 获取并返回密钥的字节表示
        //return new byte[0];
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof SessionKey) {
            SessionKey other = (SessionKey) obj;
            return Arrays.equals(this.getKeyBytes(), other.getKeyBytes());
        }
        return false;
    }

    /*
     * 覆盖 hashCode 方法，以确保与 equals 方法一致
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(this.getKeyBytes());
    }

    /*
     * 生成一个随机的初始化向量（IV）
     */
        public byte[] generateIV() {
        byte[] iv = new byte[16]; // AES 的块大小是 16 字节
        new java.security.SecureRandom().nextBytes(iv); // 使用安全随机数生成器生成随机 IV
        return iv;
        }
}


