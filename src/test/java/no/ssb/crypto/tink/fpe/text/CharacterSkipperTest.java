package no.ssb.crypto.tink.fpe.text;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static no.ssb.crypto.tink.fpe.text.CharacterGroup.ALPHANUMERIC;
import static org.assertj.core.api.Assertions.assertThat;

class CharacterSkipperTest {

    final String longText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n" +
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.\n" +
            "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

    @ParameterizedTest
    @ValueSource(strings = {"foo", longText})
    void characterSkipper_textWithoutUnknownCharacters_shouldReturnUnprocessedText(String text) {
        CharacterSkipper skipper = CharacterSkipper.of(text, ALPHANUMERIC.getChars() + CharacterGroup.SPACE.getChars() + ",.\n");
        assertThat(skipper.hasSkipped()).isFalse();
        assertThat(skipper.getProcessedText()).isEqualTo(text);
    }

    @ParameterizedTest
//    @NullAndEmptySource
    @ValueSource(strings = {"f o o", longText})
    void characterSkipper_textWithUnknownCharacters_shouldRemoveCharsFromProcessedTextAndBeAbleToRebuild(String text) {
        CharacterSkipper skipper = CharacterSkipper.of(text, ALPHANUMERIC.getChars());
        assertThat(skipper.hasSkipped()).isTrue();
        StringBuilder rebuilt = new StringBuilder(skipper.getProcessedText());
        skipper.injectSkippedInto(rebuilt);
        assertThat(rebuilt.toString()).isEqualTo(text);
    }

}