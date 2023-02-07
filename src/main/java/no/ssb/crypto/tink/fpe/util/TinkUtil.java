package no.ssb.crypto.tink.fpe.util;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class TinkUtil {

    public static String toKeysetJson(KeysetHandle keysetHandle) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(baos));
        return new String(baos.toByteArray());
    }

    public static KeysetHandle readKeyset(String keysetJson) throws GeneralSecurityException, IOException {
        return CleartextKeysetHandle.read(JsonKeysetReader.withString(keysetJson));
    }

}
