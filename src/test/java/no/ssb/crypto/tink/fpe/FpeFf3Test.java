package no.ssb.crypto.tink.fpe;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import no.ssb.crypto.tink.fpe.util.TinkUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static no.ssb.crypto.tink.fpe.FpeFfxKeyType.FPE_FF31_256_ALPHANUMERIC;
import static no.ssb.crypto.tink.fpe.UnknownCharacterStrategy.*;
import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.b2s;
import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.s2b;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class FpeFf3Test {

    private final static String KEYSET_JSON_FF31_256_ALPHANUMERIC = "{\"primaryKeyId\":1720617146,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/ssb.crypto.tink.FpeFfxKey\",\"value\":\"EiBoBeUFkoew7YJObcgcz1uOmzdhJFkPP7driAxAuS0UiRpCEAIaPkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":1720617146,\"outputPrefixType\":\"RAW\"}]}";
    private final static String KEYSET_JSON_FF31_192_ALPHANUMERIC = "{\"primaryKeyId\":1928982491,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/ssb.crypto.tink.FpeFfxKey\",\"value\":\"EhizrnA3ckTddEhK3xWtrTMe6MEGpDFGXIUaQhACGj5BQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OQ==\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":1928982491,\"outputPrefixType\":\"RAW\"}]}";
    private final static String KEYSET_JSON_FF31_128_ALPHANUMERIC = "{\"primaryKeyId\":1382079328,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/ssb.crypto.tink.FpeFfxKey\",\"value\":\"EhD4978shQNRpBNaBjbF4KO4GkIQAho+QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":1382079328,\"outputPrefixType\":\"RAW\"}]}";

    private final static String longText = "CHAPTER 1. Loomings.\n" +
            "\n" +
            "Call me Ishmael. Some years ago—never mind how long precisely—having\n" +
            "little or no money in my purse, and nothing particular to interest me\n" +
            "on shore, I thought I would sail about a little and see the watery part\n" +
            "of the world. It is a way I have of driving off the spleen and\n" +
            "regulating the circulation. Whenever I find myself growing grim about\n" +
            "the mouth; whenever it is a damp, drizzly November in my soul; whenever\n" +
            "I find myself involuntarily pausing before coffin warehouses, and\n" +
            "bringing up the rear of every funeral I meet; and especially whenever\n" +
            "my hypos get such an upper hand of me, that it requires a strong moral\n" +
            "principle to prevent me from deliberately stepping into the street, and\n" +
            "methodically knocking people’s hats off—then, I account it high time to\n" +
            "get to sea as soon as I can. This is my substitute for pistol and ball.\n" +
            "With a philosophical flourish Cato throws himself upon his sword; I\n" +
            "quietly take to the ship. There is nothing surprising in this. If they\n" +
            "but knew it, almost all men in their degree, some time or other,\n" +
            "cherish very nearly the same feelings towards the ocean with me.";

    private final static String TWEAK = b2s(new byte[0]);

    @BeforeAll
    static void initTink() throws Exception {
        FpeConfig.register();
    }

    @Test
    void staticKey_encryptUnknownCharsWithDefaultParams_shouldFail() throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_128_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        String plaintext = "Blah!";
        assertThatExceptionOfType(IncompatiblePlaintextException.class)
                .isThrownBy(() -> {
                    fpe.encrypt(s2b(plaintext));
                })
                .withMessage("Plaintext can only contain characters from the alphabet 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'");
    }

    @Test
    void staticKey_encryptAndDecryptLongText() throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_256_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        FpeParams params = FpeParams.with().unknownCharacterStrategy(SKIP);

        String plaintext = longText;
        byte[] ciphertext = fpe.encrypt(s2b(plaintext), params);
        byte[] decrypted = fpe.decrypt(ciphertext, params);
        assertThat(b2s(decrypted)).isEqualTo(plaintext);
    }

    @Test
    void staticKey_encryptAndDecryptWithCustomRedactChar() throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_192_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        FpeParams params = FpeParams.with().unknownCharacterStrategy(REDACT).redactionChar('Q');

        String plaintext = "Foo Bar";
        byte[] ciphertext = fpe.encrypt(s2b(plaintext), params);
        byte[] decrypted = fpe.decrypt(ciphertext, params);
        assertThat(b2s(decrypted)).isEqualTo("FooQBar");
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            "Foobar;6jZemW",
            "Foo bar;6jZ emW",
            "If I could gather all the stars and hold them in my hand;Tw 8 Vqp9k FVfYSv DqJ eSe 5nL68 BA8 SkV8 vhX4 Dc SP XImS",
            "A;A",
            "123;123",
            "abcd;QCeY",
            "ab cd;QC eY",
            "abc#;abc#",
            "012345678901234567890123456789AB;ULxO2Z2FeOfIpESyrRCBIj2bABCu4sAB",
            "012345678901234567890123456789#;ULxO2Z2FeOfIpESyrRCBIj2bABCu4s#"
    })
    void ff31_encrypt_decrypt_alphanumeric_with_skip(String plaintext, String expectedCiphertext) throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_256_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        FpeParams params = FpeParams.with().unknownCharacterStrategy(SKIP);

        byte[] ciphertext = fpe.encrypt(s2b(plaintext), params);
        assertThat(b2s(ciphertext)).isEqualTo(expectedCiphertext);
        byte[] decrypted = fpe.decrypt(ciphertext, params);
        assertThat(b2s(decrypted)).isEqualTo(plaintext);
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            "Foobar;6jZemW;Foobar",
            "Foo bar;qFejvAC;FooXbar",
            "If I could gather all the stars and hold them in my hand;qslVtH0Zu2Gcy3I89NeWRwGShILxssNPGM7LABI8wxLcY23UGevd2NaV;IfXIXcouldXgatherXallXtheXstarsXandXholdXthemXinXmyXhand",
            "A;A;A",
            "123;123;123",
            "abcd;QCeY;abcd",
            "ab cd;KtxVK;abXcd",
            "abc#;SuU6;abcX",
            "012345678901234567890123456789AB;ULxO2Z2FeOfIpESyrRCBIj2bABCu4sAB;012345678901234567890123456789AB",
            "012345678901234567890123456789#;ULxO2Z2FeOfIpESyrRCBIj2bABCu4sX;012345678901234567890123456789X"
    })
    void ff31_encrypt_decrypt_alphanumeric_with_redact(String plaintext, String expectedCiphertext, String expectedPlaintext) throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_256_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        FpeParams params = FpeParams.with().unknownCharacterStrategy(REDACT);

        byte[] ciphertext = fpe.encrypt(s2b(plaintext), params);
        assertThat(b2s(ciphertext)).isEqualTo(expectedCiphertext);
        byte[] decrypted = fpe.decrypt(ciphertext, params);
        assertThat(b2s(decrypted)).isEqualTo(expectedPlaintext);
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            "Foobar;6jZemW;Foobar",
            "Foo bar;6jZemW;Foobar",
            "If I could gather all the stars and hold them in my hand;Tw8Vqp9kFVfYSvDqJeSe5nL68BA8SkV8vhX4DcSPXImS;IfIcouldgatherallthestarsandholdtheminmyhand",
            "A;A;A",
            "123;123;123",
            "abcd;QCeY;abcd",
            "ab cd;QCeY;abcd",
            "abc#;abc;abc",
            "012345678901234567890123456789AB;ULxO2Z2FeOfIpESyrRCBIj2bABCu4sAB;012345678901234567890123456789AB",
            "012345678901234567890123456789#;ULxO2Z2FeOfIpESyrRCBIj2bABCu4s;012345678901234567890123456789"
    })
    void ff31_encrypt_decrypt_alphanumeric_with_delete(String plaintext, String expectedCiphertext, String expectedPlaintext) throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_256_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        FpeParams params = FpeParams.with().unknownCharacterStrategy(DELETE);

        byte[] ciphertext = fpe.encrypt(s2b(plaintext), params);
        assertThat(b2s(ciphertext)).isEqualTo(expectedCiphertext);
        byte[] decrypted = fpe.decrypt(ciphertext, params);
        assertThat(b2s(decrypted)).isEqualTo(expectedPlaintext);
    }

    @Test
    void createKey() throws Exception {
        KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get(FPE_FF31_256_ALPHANUMERIC.name()));
        String keyset = TinkUtil.toKeysetJson(keysetHandle);
        System.out.println(keyset);
    }

    @Test
    void ff31_encrypt_decrypt_with_different_string_encoding() throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_256_ALPHANUMERIC);
        Fpe fpe = keysetHandle.getPrimitive(Fpe.class);
        FpeParams paramsUtf8 = FpeParams.with().unknownCharacterStrategy(SKIP);
        FpeParams paramsLatin1 = FpeParams.with().unknownCharacterStrategy(SKIP).charset(StandardCharsets.ISO_8859_1);
        String plaintextStr = "Lörem ïpsum dôlor sit ämêt.";  // funny characters

        // utf-8
        byte[] utf8Plaintext = plaintextStr.getBytes(StandardCharsets.UTF_8);
        byte[] utf8Ciphertext = fpe.encrypt(utf8Plaintext, paramsUtf8);
        byte[] utf8PlaintextRestored = fpe.decrypt(utf8Ciphertext, paramsUtf8);
        assertThat(utf8PlaintextRestored).isEqualTo(utf8Plaintext);

        // latin-1 (ISO-8859-1)
        byte[] latin1Plaintext = plaintextStr.getBytes(StandardCharsets.ISO_8859_1);
        byte[] latin1Ciphertext = fpe.encrypt(latin1Plaintext, paramsLatin1);
        byte[] latin1PlaintextRestored = fpe.decrypt(latin1Ciphertext, paramsLatin1);
        assertThat(latin1Plaintext).isEqualTo(latin1PlaintextRestored);

        // Ensure the original and restored plaintexts match, regardless of the encoding used.
        assertThat(utf8PlaintextRestored).isEqualTo(utf8PlaintextRestored);

        // Ciphertexts will be different if using different encodings
        assertThat(utf8Ciphertext).isNotEqualTo(latin1Ciphertext);
    }

}
