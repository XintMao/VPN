import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class NetPipeServer {
    private static Arguments arguments;
    private static HandshakeCrypto privateKey;
    private static SessionKey sessionKey;
    //private static byte[] iv;

    private static SessionCipher sessionCipher;
    private static HandshakeMessage sessionMessage;
    private static HandshakeMessage clientHello;
    private static Socket socket;

    public static void main(String[] args) {
        try {
            // 解析参数并加载证书和密钥
            parseArgs(args);
            NetCert netCert = new NetCert();
            netCert.setCaCert(CertificateManager.loadCACertificate(arguments.get("cacert"), "ca-np.ik2206.kth.se"));
            netCert.setServerCert(CertificateManager.loadCACertificate(arguments.get("usercert"), "server-np.ik2206.kth.se"));
            NetDigest netDigest = new NetDigest();
            netDigest.setServerCrypto(CertificateManager.loadPrivateKey(arguments.get("key")));

            int port = Integer.parseInt(arguments.get("port"));
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                System.out.println("Server listening on port " + port);
                socket = serverSocket.accept();

                // 握手过程：逐步拆分逻辑
                checkClientHello(socket, netCert, netDigest);
                sendServerHello(socket, netCert, netDigest);
                handleSession(socket, netDigest);
                sendServerFinished(netDigest.getDigest(), netDigest.getServerCrypto(), socket);
                checkClientFinished(socket, netDigest);

                // 转发加密会话流
                Forwarder.forwardStreams(
                        System.in,
                        System.out,
                        sessionCipher.openDecryptedInputStream(socket.getInputStream()),
                        sessionCipher.openEncryptedOutputStream(socket.getOutputStream()),
                        socket
                );
            }
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1); // 退出程序
        }
    }


    private static void parseArgs(String[] args) throws Exception {
        arguments = new Arguments();

        // 定义参数规范
        arguments.setArgumentSpec("port", "Server port number");
        arguments.setArgumentSpec("usercert", "Server certificate file");
        arguments.setArgumentSpec("cacert", "CA certificate file");
        arguments.setArgumentSpec("key", "Server private key file");

        try {
            // 加载命令行参数
            arguments.loadArguments(args);

            // 验证必需的参数是否存在
            arguments.setArgumentSpec("port", "portnumber");
            arguments.setArgumentSpec("usercert", "filename");
            arguments.setArgumentSpec("cacert", "filename");
            arguments.setArgumentSpec("key", "filename");
        } catch (IllegalArgumentException e) {
            usage(); // 提示用法并退出程序
        }
    }


    private static void usage() {
        System.err.println("Usage: java NetPipeServer --port=<port> --usercert=<path> --cacert=<path> --key=<path>");
        System.exit(1); // 退出程序
    }


    private static void checkClientHello(Socket socket, NetCert netCert, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        // System.out.println("SERVER: Waiting for CLIENTHELLO message...");
        // 接收 CLIENTHELLO 消息
        HandshakeMessage clientHello = HandshakeMessage.recv(socket);
        // 验证消息类型
        if (clientHello == null || clientHello.getType() != HandshakeMessage.MessageType.CLIENTHELLO) {
            throw new Exception("Invalid message type received. Expected CLIENTHELLO.");
        }
        // 验证并加载客户端证书
        netCert.setClientCert(CertificateManager.loadVerifiedCACertificate(clientHello.getParameter("Certificate"), netCert.getCaCert(), "client-np.ik2206.kth.se"));
        // 初始化客户端加密对象
        netDigest.setClientCrypto(new HandshakeCrypto(netCert.getClientCert()));

        // 初始化客户端消息摘要
        netDigest.setDigest(new HandshakeDigest());
        netDigest.setClientDigest(new HandshakeDigest());
        netDigest.getClientDigest().update(clientHello.getBytes());
        //  System.out.println("DEBUG: Received CLIENTHELLO Bytes: " + Arrays.toString(clientHello.getBytes()));
        //System.out.println("DEBUG: Received CLIENTHELLO Message: " + clientHello.toString());
        //  System.out.println("SERVER: CLIENTHELLO verification successful!");
    }

    private static void sendServerHello(Socket socket, NetCert netCert, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        // 创建 SERVERHELLO 消息
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        // 编码证书
        String certB64 = Base64.getEncoder().encodeToString(netCert.getServerCert().getBytes());
        serverHello.putParameter("Certificate", certB64);
        // 发送消息
        serverHello.send(socket);
        // 更新消息摘要
        netDigest.getDigest().update(serverHello.getBytes());
        //  System.out.println("SERVER: SERVERHELLO sent successfully!");

    }

    private static void handleSession(Socket socket, NetDigest netDigest) throws Exception {
        if (socket == null) {
            return;
        }
        // 接收 SESSION 消息
        sessionMessage = HandshakeMessage.recv(socket);

        // 验证消息类型
        if (sessionMessage == null || sessionMessage.getType() != HandshakeMessage.MessageType.SESSION) {
            throw new Exception("Invalid message type: Expected SESSION");
        }

        // 获取加密的 SessionKey 和 IV
        String encryptedSessionKeyBase64 = sessionMessage.getParameter("SessionKey");
        String encryptedIVBase64 = sessionMessage.getParameter("SessionIV");

        if (encryptedSessionKeyBase64 == null || encryptedIVBase64 == null || encryptedSessionKeyBase64.isEmpty() || encryptedIVBase64.isEmpty()) {
            throw new Exception("SESSION message missing parameters");
        }

        // 解密 SessionKey 和 IV
        byte[] encryptedSessionKey = Base64.getDecoder().decode(encryptedSessionKeyBase64);
        byte[] encryptedIV = Base64.getDecoder().decode(encryptedIVBase64);

        byte[] sessionKeyBytes = netDigest.getServerCrypto().decrypt(encryptedSessionKey);
        byte[] ivBytes = netDigest.getServerCrypto().decrypt(encryptedIV);

        // 初始化会话密钥和加密对象
        sessionKey = new SessionKey(sessionKeyBytes);
        sessionCipher = new SessionCipher(sessionKey, ivBytes);

        // 更新消息摘要
        netDigest.getClientDigest().update(sessionMessage.getBytes());

        //  System.out.println("SERVER: Session key and IV successfully decrypted and session cipher initialized.");
        // System.out.println("DEBUG: SessionKey: " + Base64.getEncoder().encodeToString(sessionKeyBytes));
        //  System.out.println("DEBUG: SessionIV: " + Base64.getEncoder().encodeToString(ivBytes));
    }

    private static void checkClientFinished(Socket socket, NetDigest netDigest) throws Exception {

        // System.out.println("SERVER: Waiting for CLIENTFINISHED message...");

        // 接收 CLIENTFINISHED 消息
        HandshakeMessage clientFinished = HandshakeMessage.recv(socket);
        if (clientFinished.getType() != HandshakeMessage.MessageType.CLIENTFINISHED) {
            throw new Exception("Invalid message type. Expected CLIENTFINISHED.");
        }

        // 验证签名
        byte[] encryptedSignature = Base64.getDecoder().decode(clientFinished.getParameter("Signature"));
        if (encryptedSignature == null) {
            throw new Exception("CLIENTFINISHED message is missing the Signature parameter.");
        }
        byte[] decryptedSignature = netDigest.getClientCrypto().decrypt(encryptedSignature);
        if (!Arrays.equals(netDigest.getClientDigest().digest(), decryptedSignature)) {
            throw new Exception("Invalid signature detected.");
        }

        // 验证时间戳
        byte[] encryptedTimestamp = Base64.getDecoder().decode(clientFinished.getParameter("TimeStamp"));
        if (encryptedTimestamp == null) {
            throw new Exception("CLIENTFINISHED message is missing the TimeStamp parameter.");
        }
        byte[] decryptedTimestamp = netDigest.getClientCrypto().decrypt(encryptedTimestamp);
        String timestamp = new String(decryptedTimestamp, StandardCharsets.UTF_8);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date messageTime = dateFormat.parse(timestamp);
        Date currentTime = new Date();

        long timeDiff = Math.abs(currentTime.getTime() - messageTime.getTime());
        if (timeDiff > 3000) {
            throw new Exception("Timeout. The timestamp difference exceeds 3 seconds.");
        }

        //  System.out.println("SERVER: ClientFinished verified successfully!");
    }


    private static void sendServerFinished(HandshakeDigest digest, HandshakeCrypto crypto, Socket socket)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, IOException {
        if (socket == null) {
            return;
        }
        // 创建 SERVERFINISHED 类型的 HandshakeMessage
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);

        // 使用 digest 生成签名摘要
        byte[] digestBytes = digest.digest();
        byte[] encryptedDigest = crypto.encrypt(digestBytes);
        serverFinished.putParameter("Signature", Base64.getEncoder().encodeToString(encryptedDigest));

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = dateFormat.format(new Date());
        byte[] encryptedTimestamp = crypto.encrypt(timestamp.getBytes(StandardCharsets.UTF_8));
        serverFinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(encryptedTimestamp));

        serverFinished.send(socket);
        // System.out.println("Server Finished message sent.");
    }

}
