import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;


public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    private static SessionKey sessionKey;
    private static HandshakeMessage clientHello;
    private static HandshakeMessage sessionMessage;
    private static SessionCipher sessionCipher;
    private static Socket socket; // 定义为静态成员变量

    public static void main(String[] args) {
        try {
            NetCert netCert = new NetCert();
            NetDigest netDigest = new NetDigest();
            parseArgs(args);

            // 加载证书和私钥
            netCert.setCaCert(CertificateManager.loadCACertificate(arguments.get("cacert"), "ca-np.ik2206.kth.se"));
            // System.out.println("DEBUG: Loaded CA certificate.");
            netCert.setClientCert(CertificateManager.loadCACertificate(arguments.get("usercert"), "client-np.ik2206.kth.se"));
            //  System.out.println("DEBUG: Loaded client certificate.");
            netDigest.setClientCrypto(CertificateManager.loadPrivateKey(arguments.get("key")));
            // System.out.println("DEBUG: Loaded private key.");


            // 获取服务器地址和端口
            String host = arguments.get("host");
            int port = Integer.parseInt(arguments.get("port"));

            // 创建 Socket 连接
            socket = new Socket(host, port); 
            //  System.out.println("Connected to server: " + host + ":" + port);

            // 执行握手过程
            sendClientHello(socket, netCert, netDigest);
            receiveAndVerifyServerHello(socket, netCert, netDigest);
            sendSessionMessage(socket, netDigest);
            verifyServerFinished(socket, netCert, netDigest);
            sendClientFinished(socket, netDigest);
            //  System.out.println("DEBUG: Forwarding streams...");
            // 转发加密数据流
            Forwarder.forwardStreams(
                    System.in,
                    System.out,
                    sessionCipher.openDecryptedInputStream(socket.getInputStream()),
                    sessionCipher.openEncryptedOutputStream(socket.getOutputStream()),
                    socket
            );

        } catch (Exception ex) {
            System.err.println("Error during handshake or session: " + ex.getMessage());
            ex.printStackTrace();
        } finally {
            // 确保关闭 Socket
            if (socket != null) {
                try {
                    socket.close();
                    //    System.out.println("Socket closed successfully.");
                } catch (IOException e) {
                    System.err.println("Error while closing socket: " + e.getMessage());
                }
            }
        }
    }

    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
        System.exit(1);
    }

    private static void parseArgs(String[] args) throws Exception {
        arguments = new Arguments();

        // 设置参数规范
        arguments.setArgumentSpec("host", "server IP or hostname");
        arguments.setArgumentSpec("port", "port number");
        arguments.setArgumentSpec("usercert", "client certificate file");
        arguments.setArgumentSpec("cacert", "CA certificate file");
        arguments.setArgumentSpec("key", "client private key file");

        try {
            
            arguments.loadArguments(args);

        } catch (IllegalArgumentException e) {
            System.err.println("Invalid arguments: " + e.getMessage());
            usage();
        } catch (Exception e) {
            throw new Exception("Error during arguments parsing and validation: " + e.getMessage(), e);
        }
    }

    private static void sendClientHello(Socket socket, NetCert netCert, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        Base64.Encoder encoder = Base64.getEncoder();
        String certB64 = encoder.encodeToString(netCert.getClientCert().getBytes());
        clientHello.putParameter("Certificate", certB64);
        //("DEBUG: CLIENTHELLO Message Bytes: " + Arrays.toString(clientHello.getBytes()));
        clientHello.send(socket);
        netDigest.setClientDigest(new HandshakeDigest());
        netDigest.getClientDigest().update(clientHello.getBytes());
    }

    private static void receiveAndVerifyServerHello(Socket socket, NetCert netCert, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        HandshakeMessage serverHello = HandshakeMessage.recv(socket);
        if (serverHello.getType() != HandshakeMessage.MessageType.SERVERHELLO) {
            throw new Exception("Invalid message type. Expected SERVERHELLO.");
        }
        netCert.setServerCert(CertificateManager.loadVerifiedCACertificate(
                serverHello.getParameter("Certificate"), netCert.getCaCert(), "server-np.ik2206.kth.se"
        ));
        netDigest.setServerCrypto(new HandshakeCrypto(netCert.getServerCert()));
        netDigest.setDigest(new HandshakeDigest());
        netDigest.getDigest().update(serverHello.getBytes());
        // System.out.println("SERVERHELLO and certificate verification successful!");
    }

    private static void sendSessionMessage(Socket socket, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        sessionKey = new SessionKey(128);
        sessionCipher = new SessionCipher(sessionKey);
        byte[] encryptedKey = netDigest.getServerCrypto().encrypt(sessionKey.getKeyBytes());
        byte[] encryptedIV = netDigest.getServerCrypto().encrypt(sessionCipher.getIVBytes());
        HandshakeMessage sessionMsg = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        sessionMsg.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedKey));
        sessionMsg.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIV));
        sessionMsg.send(socket);
        netDigest.getClientDigest().update(sessionMsg.getBytes());

    }

    private static void sendClientFinished(Socket socket, NetDigest netDigest) throws Exception {
        HandshakeMessage clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);

        // 传递 socket 参数
        sendFinishedMessage(clientFinished, netDigest.getClientDigest(), netDigest.getClientCrypto(), socket);

    }

    private static void verifyServerFinished(Socket socket, NetCert netCert, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        HandshakeMessage serverFinished = HandshakeMessage.recv(socket);
        if (serverFinished == null || serverFinished.getType() != HandshakeMessage.MessageType.SERVERFINISHED) {
            throw new Exception("Invalid or missing ServerFinished message.");
        }
        HandshakeCrypto crypto = new HandshakeCrypto(netCert.getServerCert());
        byte[] decryptedSignature = crypto.decrypt(Base64.getDecoder().decode(serverFinished.getParameter("Signature")));
        if (!Arrays.equals(netDigest.getDigest().digest(), decryptedSignature)) {
            throw new Exception("Invalid ServerFinished signature.");
        }
        // check the timestamp
        byte[] encryptedTimestamp = Base64.getDecoder().decode(serverFinished.getParameter("TimeStamp"));
        byte[] decryptedTimestamp = netDigest.getServerCrypto().decrypt(encryptedTimestamp);
        String timestamp = new String(decryptedTimestamp, StandardCharsets.UTF_8);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date messageTime = dateFormat.parse(timestamp);
        Date currentTime = new Date();


        long timeDiff = Math.abs(currentTime.getTime() - messageTime.getTime());
        if (timeDiff > 3000) {
            throw new Exception("timeout");
        }

    }

    public static void sendFinishedMessage(HandshakeMessage message, HandshakeDigest digest, HandshakeCrypto crypto, Socket socket) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] digestBytes = digest.digest();
        byte[] encryptedDigest = crypto.encrypt(digestBytes);
        message.putParameter("Signature", Base64.getEncoder().encodeToString(encryptedDigest));

        // Add encrypted timestamp
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = dateFormat.format(new Date());
        byte[] encryptedTimestamp = crypto.encrypt(timestamp.getBytes(StandardCharsets.UTF_8));
        message.putParameter("TimeStamp", Base64.getEncoder().encodeToString(encryptedTimestamp));

        message.send(socket);
    }
}
