package no.ssb.crypto.tink.fpe;

import com.privacylogistics.FF3Cipher;
import org.junit.jupiter.api.Test;

public class MystoTest {

    private static final String KEY = "2DE79D232DF5585D68CE47882AE256D6";
    private static final String TWEAK = "CBD09280979564";
    private static final String TWEAK2 = "00000000000000";
    private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    @Test
    void encryptDecrypt() throws Exception {
        FF3Cipher ff3 = new FF3Cipher(KEY, TWEAK, ALPHABET);
        String plaintext = "Foobar";
        String ciphertext = ff3.encrypt(plaintext, TWEAK);

        System.out.println("key:        " + KEY);
        System.out.println("tweak:      " + TWEAK);
        System.out.println("plaintext:  " + plaintext);
        System.out.println("ciphertext: " + ciphertext);
    }

}
