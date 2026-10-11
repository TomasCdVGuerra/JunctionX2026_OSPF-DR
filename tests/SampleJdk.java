import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class SampleJdk {
    static final String WEAK = "MD5";
    static final String CIPHER_ALGO = "DES";
    static final String PREFIX = "AES/";
    static final String ECB_FULL = PREFIX + "ECB/PKCS5Padding";
    private String instanceAlgo = "DESede";

    @interface Foo { String algo(); }
    static class Fake { Object getInstance(String s) { return null; } }
    static Fake factory() { return new Fake(); }
    static Object getInstance(String s) { return null; }

    void hashes(byte[] key) throws Exception {
        MessageDigest.getInstance("MD5");                         // EXPECT 1
        MessageDigest.getInstance("md5");                         // EXPECT 1  case-insensitive
        MessageDigest.getInstance("SHA-1");                       // EXPECT 1
        MessageDigest.getInstance("SHA1");                        // EXPECT 1
        MessageDigest.getInstance("SHA");                         // EXPECT 1  "SHA" == SHA-1
        MessageDigest.getInstance("MD2");                         // EXPECT 1
        MessageDigest.getInstance("MD5", "SUN");                  // EXPECT 1  com provider
        java.security.MessageDigest.getInstance("MD5");           // EXPECT 1  totalmente qualificado
        MessageDigest.getInstance(WEAK);                          // EXPECT 1  via constante
        MessageDigest.getInstance("M" + "D5");                    // EXPECT 1  concatenacao
        MessageDigest.getInstance("md5".toUpperCase());           // EXPECT 1  .toUpperCase()
        MessageDigest.getInstance(                                // EXPECT 1  multilinha
            "SHA-1");
        MessageDigest.getInstance("MD5").digest(key);             // EXPECT 1  encadeado: so 1
        Mac.getInstance("HmacMD5");                               // EXPECT 1
        Mac.getInstance("HmacSHA1");                              // EXPECT 1
        Signature.getInstance("SHA1withRSA");                     // EXPECT 1
        Signature.getInstance("MD5withRSA");                      // EXPECT 1
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");       // EXPECT 1

        String algo = "SHA-256";
        algo = "MD5";
        MessageDigest.getInstance(algo);                          // EXPECT 1  ambiguo (um dos valores e fraco)

        String quote = "http://exemplo.com";  MessageDigest.getInstance("MD5");   // EXPECT 1  "//" dentro de string
        char aspas = '"';
        MessageDigest.getInstance("MD5");                         // EXPECT 1  depois de char com aspas
    }

    void ciphers(byte[] key, String unknown) throws Exception {
        Cipher.getInstance("AES");                                // EXPECT 1  default do Java = ECB
        Cipher.getInstance("AES/ECB/PKCS5Padding");               // EXPECT 1
        Cipher.getInstance("aes/ecb/nopadding");                  // EXPECT 1
        Cipher.getInstance("AES_128/ECB/NoPadding");              // EXPECT 1
        Cipher.getInstance(ECB_FULL);                             // EXPECT 1  constante que usa outra constante
        Cipher.getInstance("DES/CBC/PKCS5Padding");               // EXPECT 1
        Cipher.getInstance("DES");                                // EXPECT 1
        Cipher.getInstance("DESede/CBC/PKCS5Padding");            // EXPECT 1
        Cipher.getInstance("RC4");                                // EXPECT 1
        Cipher.getInstance("ARCFOUR");                            // EXPECT 1
        Cipher.getInstance("Blowfish");                           // EXPECT 1
        Cipher.getInstance("RC2");                                // EXPECT 1
        Cipher.getInstance(CIPHER_ALGO);                          // EXPECT 1  via constante
        Cipher.getInstance(instanceAlgo);                         // EXPECT 1  via campo
        Cipher.getInstance(this.instanceAlgo);                    // EXPECT 1  via this.campo
        Cipher.getInstance("PBEWithMD5AndDES");                   // EXPECT 1
        KeyGenerator.getInstance("DES");                          // EXPECT 1
        SecretKeyFactory.getInstance("DESede");                   // EXPECT 1
        new SecretKeySpec(key, "DES");                            // EXPECT 1
        new SecretKeySpec(key, "RC4");                            // EXPECT 1
        String local = "DES";
        Cipher.getInstance(local);                                // EXPECT 1  via variavel local
    }

    void safe(byte[] key, String unknown) throws Exception {
        MessageDigest.getInstance("SHA-256");                     // OK
        MessageDigest.getInstance("SHA-512");                     // OK
        MessageDigest.getInstance("SHA3-256");                    // OK
        Mac.getInstance("HmacSHA256");                            // OK
        Signature.getInstance("SHA256withRSA");                   // OK
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");     // OK
        Cipher.getInstance("AES/GCM/NoPadding");                  // OK
        Cipher.getInstance("AES/CBC/PKCS5Padding");               // OK
        Cipher.getInstance("AES/CTR/NoPadding");                  // OK
        Cipher.getInstance("RSA/ECB/PKCS1Padding");               // OK  ECB em RSA nao e problema
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // OK
        Cipher.getInstance("PBEWithHmacSHA256AndAES_128");        // OK
        KeyGenerator.getInstance("AES");                          // OK
        new SecretKeySpec(key, "AES");                            // OK
        Cipher.getInstance(unknown);                              // OK  nao resolvivel estaticamente
        MessageDigest.getInstance(unknown + "x");                 // OK
        factory().getInstance("MD5");                             // OK  raiz nao resolvivel
        getInstance("MD5");                                       // OK  metodo proprio, sem import static
        // MessageDigest.getInstance("MD5");                      // OK  comentario
        /* Cipher.getInstance("DES"); */                          // OK  comentario de bloco
        String s = "MessageDigest.getInstance(\"MD5\")";          // OK  texto dentro de string
        String block = """
            MessageDigest.getInstance("MD5")
            Cipher.getInstance("DES")
            """;
    }

    @Foo(algo = "DES")
    void annotated(String algo) throws Exception {
        Cipher.getInstance(algo);                                 // OK  parametro de anotacao nao e constante
    }
}
