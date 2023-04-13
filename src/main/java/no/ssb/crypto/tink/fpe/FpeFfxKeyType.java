package no.ssb.crypto.tink.fpe;

import no.ssb.crypto.tink.fpe.text.CharacterGroup;
import no.ssb.crypto.tink.proto.FfxMode;

import static no.ssb.crypto.tink.proto.FfxMode.FF31;

public enum FpeFfxKeyType {

    /**
     * FF3-1 (256 bits) key with alphanumeric alphabet (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz)
     */
    FPE_FF31_256_ALPHANUMERIC(FF31, 256, CharacterGroup.ALPHANUMERIC),

    /**
     * FF3-1 (192 bits) key with alphanumeric alphabet (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz)
     */
    FPE_FF31_192_ALPHANUMERIC(FF31, 192, CharacterGroup.ALPHANUMERIC),

    /**
     * FF3-1 (128 bits) key with alphanumeric alphabet (0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz)
     */
    FPE_FF31_128_ALPHANUMERIC(FF31, 128, CharacterGroup.ALPHANUMERIC),

    /**
     * FF3-1 (256 bits) key with digit-only alphabet (0123456789)
     */
    FPE_FF31_256_DIGITS(FF31, 256, CharacterGroup.DIGITS),

    /**
     * FF3-1 (192 bits) key with digit-only alphabet (0123456789)
     */
    FPE_FF31_192_DIGITS(FF31, 192, CharacterGroup.DIGITS),

    /**
     * FF3-1 (128 bits) key with digit-only alphabet (0123456789)
     */
    FPE_FF31_128_DIGITS(FF31, 128, CharacterGroup.DIGITS),
    ;

    private final FfxMode mode;
    private final int keySize;
    private final CharacterGroup alphabet;

    FpeFfxKeyType(FfxMode mode, int keySize, CharacterGroup alphabet) {
        this.mode = mode;
        this.keySize = keySize;
        this.alphabet = alphabet;
    }

    public FfxMode getMode() {
        return mode;
    }

    public int getKeySize() {
        return keySize;
    }

    public CharacterGroup getAlphabet() {
        return alphabet;
    }

}
