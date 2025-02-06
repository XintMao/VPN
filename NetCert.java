
public class NetCert {

    private  HandshakeCertificate serverCert;
    private  HandshakeCertificate caCert;
    private  HandshakeCertificate clientCert;

    public HandshakeCertificate getCaCert() {
        return caCert;
    }

    public void setCaCert(HandshakeCertificate caCert) {
        this.caCert = caCert;
    }

    public HandshakeCertificate getClientCert() {
        return clientCert;
    }

    public HandshakeCertificate getServerCert() {
        return serverCert;
    }

    public void setClientCert(HandshakeCertificate clientCert) {
        this.clientCert = clientCert;
    }

    public void setServerCert(HandshakeCertificate serverCert) {
        this.serverCert = serverCert;
    }
}