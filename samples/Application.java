// SYNTHETIC static-analysis fixture. No external execution is required.
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

class Application {
    void configure() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        KeyPairGenerator keys = KeyPairGenerator.getInstance("RSA");
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
    }
}
