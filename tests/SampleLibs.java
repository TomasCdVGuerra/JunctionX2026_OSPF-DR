package demo;

import static org.apache.commons.codec.digest.DigestUtils.md5Hex;
import static org.apache.commons.codec.digest.DigestUtils.sha256Hex;
import static java.security.MessageDigest.getInstance;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import com.google.common.hash.Hashing;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.AESEngine;
import javax.crypto.spec.DESKeySpec;
import com.acme.Cipher;

class SampleLibs {
    void commons(byte[] data, byte[] k) throws Exception {
        DigestUtils.md5Hex(data);                                   // EXPECT 1
        DigestUtils.sha1Hex(data);                                  // EXPECT 1
        DigestUtils.md5(data);                                      // EXPECT 1
        DigestUtils.getMd5Digest();                                 // EXPECT 1
        DigestUtils.getDigest("MD5");                               // EXPECT 1
        DigestUtils.sha256Hex(data);                                // OK
        DigestUtils.sha512Hex(data);                                // OK
        md5Hex(data);                                               // EXPECT 1  import static
        sha256Hex(data);                                            // OK
        getInstance("MD5");                                         // EXPECT 1  import static de MessageDigest
        org.apache.commons.codec.digest.DigestUtils.md5Hex(data);   // EXPECT 1  totalmente qualificado
        new DigestUtils("SHA-1");                                   // EXPECT 1  construtor com string
        new DigestUtils("SHA-256");  // EXPECT 1  inventory: recognized algorithm; risk assessed separately
        HmacUtils.hmacMd5Hex(k, data);                              // EXPECT 1
        HmacUtils.hmacSha1(k, data);                                // EXPECT 1
        HmacUtils.hmacSha256(k, data);                              // OK
        new HmacUtils(HmacAlgorithms.HMAC_MD5, k);                  // EXPECT 1  constante (referencia)
        new HmacUtils(HmacAlgorithms.HMAC_SHA_256, k);              // OK
        MessageDigest.getInstance(MessageDigestAlgorithms.SHA_1);   // EXPECT 1  constante (referencia)
        MessageDigest.getInstance(MessageDigestAlgorithms.SHA_256); // OK
        Function<byte[], String> f = DigestUtils::md5Hex;           // EXPECT 1  referencia de metodo
    }

    void guava(byte[] k) {
        Hashing.md5();                                              // EXPECT 1
        Hashing.sha1();                                             // EXPECT 1
        Hashing.hmacMd5(k);                                         // EXPECT 1
        Hashing.sha256();                                           // OK
    }

    void bouncy(byte[] k) {
        new MD5Digest();                                            // EXPECT 1
        new SHA256Digest();                                         // OK
        new org.bouncycastle.crypto.digests.SHA1Digest();           // EXPECT 1  qualificado, sem import
        new DESEngine();                                            // EXPECT 1
        new AESEngine();                                            // OK
        new DESKeySpec(k);                                          // EXPECT 1
        Supplier<MD5Digest> s = MD5Digest::new;                     // EXPECT 1  construtor por referencia
    }

    void classeProprio() {
        Cipher.getInstance("DES");                                  // OK  Cipher aqui e com.acme.Cipher
    }
}
