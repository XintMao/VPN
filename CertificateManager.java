import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class CertificateManager {

    public static HandshakeCertificate loadCACertificate(String filename, String CN)
            throws IOException, CertificateException {
        try (FileInputStream is = new FileInputStream(filename)) {
            HandshakeCertificate certificate = new HandshakeCertificate(is);
            validateCertificateCN(certificate, CN);
            return certificate;
        }
    }

    public static HandshakeCertificate loadVerifiedCACertificate(
            String filename,
            HandshakeCertificate caCertificate,
            String CN
    ) throws CertificateException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, NoSuchProviderException {
        byte[] certBytes = Base64.getDecoder().decode(filename);
        HandshakeCertificate certificate = new HandshakeCertificate(certBytes);
        certificate.verify(caCertificate);
        validateCertificateCN(certificate, CN);
        return certificate;
    }

    public static HandshakeCrypto loadPrivateKey(String filename)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Files.readAllBytes(new File(filename).toPath());
        return new HandshakeCrypto(privateKeyBytes);
    }

    private static void validateCertificateCN(HandshakeCertificate certificate, String expectedCN)
            throws CertificateException {
        String actualCN = certificate.getCN();
        if (!expectedCN.equals(actualCN)) {
            throw new CertificateException(
                    "Invalid certificate CN: Expected " + expectedCN + ", but found " + actualCN
            );
        }
    }
}