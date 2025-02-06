public class NetDigest {

    private HandshakeCrypto serverCrypto;
    private HandshakeCrypto clientCrypto;
    private HandshakeDigest clientDigest;
    private HandshakeDigest digest;


    public HandshakeDigest getDigest() {
        return digest;
    }

    public void setDigest(HandshakeDigest digest) {
        this.digest = digest;
    }

    public HandshakeDigest getClientDigest() {
        return clientDigest;
    }

    public void setClientDigest(HandshakeDigest clientDigest) {
        this.clientDigest = clientDigest;
    }

    public HandshakeCrypto getClientCrypto() {
        return clientCrypto;
    }

    public void setClientCrypto(HandshakeCrypto clientCrypto) {
        this.clientCrypto = clientCrypto;
    }

    public HandshakeCrypto getServerCrypto() {
        return serverCrypto;
    }

    public void setServerCrypto(HandshakeCrypto serverCrypto) {
        this.serverCrypto = serverCrypto;
    }
}