package no.ssb.crypto.tink.fpe;


import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import no.ssb.crypto.tink.fpe.text.CharacterGroup;
import no.ssb.crypto.tink.proto.FfxMode;
import no.ssb.crypto.tink.proto.FpeFfxKey;
import no.ssb.crypto.tink.proto.FpeFfxKeyFormat;
import no.ssb.crypto.tink.proto.FpeFfxKeyParams;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.*;


/**
 * This key manager generates new {@code FpeFfxKey} keys and produces new instances of {@code FpeFf3}.
 */
public final class FpeFfxKeyManager extends KeyTypeManager<FpeFfxKey> {

    FpeFfxKeyManager() {
        super(
                FpeFfxKey.class,
                new PrimitiveFactory<Fpe, FpeFfxKey>(Fpe.class) {
                    @Override
                    public Fpe getPrimitive(FpeFfxKey key) throws GeneralSecurityException {
                        if (key.getParams().getMode() == FfxMode.FF31) {
                            return new FpeFf3(key.getKeyValue().toByteArray(), key.getParams().getAlphabet());
                        }
                        else {
                            throw new UnsupportedOperationException(key.getParams().getMode() + " is not a supported mode. Currently, only " + FfxMode.FF31 + " is supported");
                        }
                    }
                });
    }

    private static final Collection<Integer> SUPPORTED_KEY_SIZES = Arrays.asList(128, 192, 256);


    @Override
    public String getKeyType() {
        return "type.googleapis.com/ssb.crypto.tink.FpeFfxKey";
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
        return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public void validateKey(FpeFfxKey key) throws GeneralSecurityException {
        Validators.validateVersion(key.getVersion(), getVersion());
        if (!SUPPORTED_KEY_SIZES.contains(key.getKeyValue().size() * 8)) {
            throw new InvalidKeyException("invalid key size: " + (key.getKeyValue().size() * 8) + " bits");
        }
    }

    @Override
    public FpeFfxKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
        return FpeFfxKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public KeyFactory<FpeFfxKeyFormat, FpeFfxKey> keyFactory() {
        return new KeyFactory<FpeFfxKeyFormat, FpeFfxKey>(FpeFfxKeyFormat.class) {
            @Override
            public void validateKeyFormat(FpeFfxKeyFormat format) throws GeneralSecurityException {
                if (!SUPPORTED_KEY_SIZES.contains(format.getKeySize())) {
                    throw new InvalidKeyException("invalid key size: " + (format.getKeySize()) + " bits");
                }
            }

            @Override
            public FpeFfxKeyFormat parseKeyFormat(ByteString byteString)
                    throws InvalidProtocolBufferException {
                return FpeFfxKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
            }

            @Override
            public FpeFfxKey createKey(FpeFfxKeyFormat format) throws GeneralSecurityException {
                return FpeFfxKey.newBuilder()
                        .setParams(format.getParams())
                        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize() / 8)))
                        .setVersion(getVersion())
                        .build();
            }

            @Override
            public FpeFfxKey deriveKey(FpeFfxKeyFormat format, InputStream inputStream)
                    throws GeneralSecurityException {
                Validators.validateVersion(format.getVersion(), getVersion());

                byte[] pseudorandomness = new byte[format.getKeySize() / 8];
                try {
                    int keySizeInBits = inputStream.read(pseudorandomness) * 8;
                    if (!SUPPORTED_KEY_SIZES.contains(keySizeInBits)) {
                        throw new InvalidKeyException("invalid key size: " + keySizeInBits + " bits");
                    }

                    return FpeFfxKey.newBuilder()
                            .setKeyValue(ByteString.copyFrom(pseudorandomness))
                            .setVersion(getVersion())
                            .build();
                } catch (IOException e) {
                    throw new GeneralSecurityException("Reading pseudorandomness failed", e);
                }
            }

            @Override
            public Map<String, KeyFactory.KeyFormat<FpeFfxKeyFormat>> keyFormats()
                    throws GeneralSecurityException {

                Map<String, KeyFactory.KeyFormat<FpeFfxKeyFormat>> result = new HashMap<>();

                for (FpeFfxKeyType keyType : FpeFfxKeyType.values()) {
                    result.put(
                            keyType.name(),
                            new KeyFactory.KeyFormat<>(
                                    keyFormat(keyType.getMode(), keyType.getKeySize(), keyType.getAlphabet()),
                                    KeyTemplate.OutputPrefixType.RAW));
                }
                return Collections.unmodifiableMap(result);
            }
        };
    }

    public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
        Registry.registerKeyManager(new FpeFfxKeyManager(), newKeyAllowed);
    }

    private static FpeFfxKeyFormat keyFormat(FfxMode mode, int keySize, CharacterGroup alphabet) {
        return FpeFfxKeyFormat.newBuilder()
                .setParams(FpeFfxKeyParams.newBuilder()
                        .setMode(mode)
                        .setAlphabet(alphabet.getChars())
                        .build())
                .setKeySize(keySize)
                .build();
    }

}
