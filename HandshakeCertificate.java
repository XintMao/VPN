import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HandshakeCertificate {
    private X509Certificate certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        certificate = (X509Certificate) certFactory.generateCertificate(instream);
    }
    public HandshakeCertificate(X509Certificate cert) {
        this.certificate = cert;
    }
    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        this(new ByteArrayInputStream(certbytes));
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() {
        try {
            return certificate.getEncoded();
        } catch (CertificateException e) {
            return new byte[0];
        }
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // Use the verify method of X509Certificate
        certificate.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        X500Principal principal = certificate.getSubjectX500Principal();
        String subjectDN = principal.getName();

        // Parse out the Common Name (CN) using regex for better robustness
        Pattern pattern = Pattern.compile("CN=([^,]+)");
        Matcher matcher = pattern.matcher(subjectDN);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        X500Principal principal = certificate.getSubjectX500Principal();
        String subjectDN = principal.getName();

        // 添加调试打印，看看 subjectDN 中的内容是什么
        System.out.println("Subject DN: " + subjectDN);

        // 使用正则表达式匹配 emailAddress 或 E 字段，忽略大小写
        Pattern pattern = Pattern.compile("(?i)(?:EMAILADDRESS|E)=([^,]+)");
        Matcher matcher = pattern.matcher(subjectDN);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }

        // 处理以 OID 1.2.840.113549.1.9.1 表示的电子邮件地址字段
        Pattern oidPattern = Pattern.compile("1\\.2\\.840\\.113549\\.1\\.9\\.1=#([^,]+)");
        matcher = oidPattern.matcher(subjectDN);
        if (matcher.find()) {
            // 解析十六进制编码的电子邮件地址
            String hexString = matcher.group(1);
            byte[] bytes = hexStringToByteArray(hexString);
            return new String(bytes, StandardCharsets.UTF_8).trim();
        }

        return null;
    }

    private byte[] hexStringToByteArray(String s) {
        s = s.replaceAll("\\s+", ""); // 去掉所有空格
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
