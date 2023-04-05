package no.ssb.crypto.tink.fpe.benchmark;

import com.google.crypto.tink.KeysetHandle;
import no.ssb.crypto.tink.fpe.Fpe;
import no.ssb.crypto.tink.fpe.FpeConfig;
import no.ssb.crypto.tink.fpe.FpeParams;
import no.ssb.crypto.tink.fpe.UnknownCharacterStrategy;
import no.ssb.crypto.tink.fpe.util.TinkUtil;
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

@State(Scope.Benchmark)
public class EncryptBenchmark {

    static {
        try {
            FpeConfig.register();
        }
        catch (GeneralSecurityException e) {
            throw new RuntimeException("Error initializing Tink FPE", e);
        }
    }

    private final static String TINY = "2 chars";
    private final static String SHORT = "6 chars";
    private final static String MEDIUM = "sentence";
    private final static String LONG = "long-complex";
    private final static Map<String, String> ENCRYPT_PARAMS = Map.of(
            TINY, "AB",
            SHORT, "Foobar",
            MEDIUM, "If I cøuld gather Åll the stars ænd håld them in my hænd...",
            LONG, "CHAPTER 1. Loomings.\n" +
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
                    "cherish very nearly the same feelings towards the ocean with me."
    );

    private final static Map<String, String> DECRYPT_PARAMS = Map.of(
            TINY, "AB",
            SHORT, "6jZemW",
            MEDIUM, "WT U 1øwyY rIbuCc Å82 o2G YHOt6 ævz råd7 7juD dk Ok mædK...",
            LONG, "9jlDcz8 C. Q3tISqHV.\n" +
                    "\n" +
                    "G57B zx Di9LUBD. UFI2 iSXch doY—eBfWL qJtx ZDm 7dTJ PHPSfmy45—sF6Pjf\n" +
                    "lZHmGh 9b hG wHiNy Js 8G 0wNEQ, Ics ZZYLNog MqIuB9pGdt D8 LvV9NpkN fh\n" +
                    "Nv oR7uu, h 4NZTvwY 7 sAI0N UbVU 6gR3L P XnRx9l pIS 4ZN E3G LfDCQQ 4hPP\n" +
                    "rf jBT ezVVu. pH tq s tz1 H YqNS Bc WghESk1 tIJ 0BA ol9ask JQr\n" +
                    "BLLXeigOX4 1Yg 9cY6aotAvEu. cYZzKjPp E BilL iuH3lM CXnnIYe NPlr wgPSm\n" +
                    "ukS Oxyqx; MwCvypUd dB zJ j QJKY, CD5THSj WQ3kpZzl m0 dj bDsd; kjmKVR3K\n" +
                    "q FVR7 dQ1SFC 3Z9pts7hJRjME aswYrOq IoGTIf rFDjgR J5kUVWJOIR, l1j\n" +
                    "hbSpUgb4 ks uKh EzjV tp EaxQA zvWMyfp o PljS; NnJ swOE76mbmR 5q7tdWxY\n" +
                    "aC HgRyU xVC yIkw gH gqnIz YBA8 ii N6, JMYU vK ZTIiM6s1 f QTDUUL 2jWfV\n" +
                    "5ymzT5fJt Jp muIQMs0 GI lvpX Tc3mtVywBjMP pQPYr7S9 0ijn o5Y dnB6E1, Uo2\n" +
                    "la6PRofKXkqu 7LWnZm7m mdHEUC’p wIYG ghe—cLAo, z XuuuOKn Bz Qj69 JAM7 p8\n" +
                    "xoW wk 3pv YQ l55l 7s B sLd. husr lg Gu v1JilWizle IId QxQgJj 1n7 SPSt.\n" +
                    "A7Rd G NP0zvrUOKucMc dI3gP4jZ kbdz yMuS8X PzMWLVY X3Zi uF5 blNEE; U\n" +
                    "okyUfCY PG59 Tc via d1zz. 7l8h7 AF FP4aLzN 3csHeXgTC4 WX q73I. J0 qKGm\n" +
                    "hlu FWUr Ba, 7pe8Je CbN xW3 XW IavnU bnvYnx, BFrL kSzD Mn 3vN41,\n" +
                    "85tFSiB iHqq cqTERD pUE kSK9 87d3GvbO LN14wfe d1O n57mG FE4Z iL."
    );

    private final static String KEYSET_JSON_FF31_256_ALPHANUMERIC = "{\"primaryKeyId\":1720617146,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/ssb.crypto.tink.FpeFfxKey\",\"value\":\"EiBoBeUFkoew7YJObcgcz1uOmzdhJFkPP7driAxAuS0UiRpCEAIaPkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":1720617146,\"outputPrefixType\":\"RAW\"}]}";

    // Define sample plaintext inputs for both methods
    @Param(value = {TINY, SHORT, MEDIUM, LONG})
    public String paramName;

    public byte[] plaintextBytes;

    public byte[] ciphertextBytes;

    private Fpe fpe;
    private FpeParams fpeParams;

    // Prepare the byte array from plaintextString
    @Setup(Level.Trial)
    public void prepare() throws Exception {
        KeysetHandle keysetHandle = TinkUtil.readKeyset(KEYSET_JSON_FF31_256_ALPHANUMERIC);
        fpe = keysetHandle.getPrimitive(Fpe.class);
        fpeParams = FpeParams.with().unknownCharacterStrategy(UnknownCharacterStrategy.SKIP);

        plaintextBytes = ENCRYPT_PARAMS.get(paramName).getBytes(StandardCharsets.UTF_8);
        ciphertextBytes = DECRYPT_PARAMS.get(paramName).getBytes(StandardCharsets.UTF_8);
    }

    // Benchmark for encrypt(byte[] plaintext) method
    @Benchmark
    public byte[] encryptBytes() throws Exception {
        return fpe.encrypt(plaintextBytes, fpeParams);
    }

    @Benchmark
    public byte[] decryptBytes() throws Exception {
        return fpe.decrypt(ciphertextBytes, fpeParams);
    }

}
