package no.ssb.crypto.tink.fpe;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.b2s;
import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.s2b;
import static org.assertj.core.api.Assertions.assertThat;

class ByteArrayUtilTest {

    @Test
    void s2b2s() {
        assertThat(b2s(s2b("Foo æøå"))).isEqualTo("Foo æøå");
        assertThat(b2s(s2b("Foo æøå", StandardCharsets.UTF_8), StandardCharsets.UTF_8)).isEqualTo("Foo æøå");
        assertThat(b2s(s2b("Foo æøå", StandardCharsets.ISO_8859_1), StandardCharsets.ISO_8859_1)).isEqualTo("Foo æøå");
    }

}