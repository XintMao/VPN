import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class FileDigest {
    public static void main(String[] args) {
        // 检查是否提供了文件名参数
        if (args.length != 1) {
            System.err.println("Usage: java FileDigest <filename>");
            System.exit(1);
        }

        // 获取文件名
        String filename = args[0];
        try {
            // 读取文件内容为字节数组
            byte[] fileContent = Files.readAllBytes(Paths.get(filename));

            // 创建HandshakeDigest实例
            HandshakeDigest digest = new HandshakeDigest();

            // 更新digest的内容
            digest.update(fileContent);

            // 获取最终的哈希值
            byte[] hash = digest.digest();

            // 将哈希值转换为Base64字符串
            String base64Hash = Base64.getEncoder().encodeToString(hash);

            // 打印Base64编码的哈希值
            System.out.println(base64Hash);

        } catch (IOException e) {
            // 处理文件读取错误
            System.err.println("Error reading file: " + e.getMessage());
            System.exit(1);
        }
    }
}