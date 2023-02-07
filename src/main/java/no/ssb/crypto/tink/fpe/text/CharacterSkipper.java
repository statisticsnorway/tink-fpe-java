package no.ssb.crypto.tink.fpe.text;


import com.google.common.base.CharMatcher;
import lombok.Value;

import java.util.ArrayList;
import java.util.List;

/**
 * CharacterSkipper is used for removing "non-allowed" characters from a string.
 *
 * It keeps track of removed/skipped characters including their original indexes, and provides a function for
 * injecting these characters at their respective indexes.
 */
public class CharacterSkipper {
    private final List<IndexedCharacter> skipped = new ArrayList<>();
    private final String processedText;
    private final CharMatcher filter;

    public CharacterSkipper(String text, String allowedChars) {
        filter = CharMatcher.noneOf(allowedChars);
        StringBuilder retained = new StringBuilder();
        char[] textChars = text.toCharArray();
        for (int i = 0; i < textChars.length; i++) {
            if (filter.matches(textChars[i])) {
                skipped.add(new IndexedCharacter(i, textChars[i]));
            }
            else {
                retained.append(textChars[i]);
            }
        }
        processedText = retained.toString();
    }

    /**
     * @return the text with "non-allowed" characters removed
     */
    public String getProcessedText() {
        return processedText;
    }

    /**
     * @return true if the CharacterSkipper has removed any characters
     */
    public boolean hasSkipped() {
        return ! skipped.isEmpty();
    }

    /**
     * Inject skipped characters at their respective indexes into a string.
     *
     * @param text the StringBuilder to be injected with skipped characters
     */
    public void injectSkippedInto(StringBuilder text) {
        for (IndexedCharacter c : skipped) {
            text.insert(c.getPos(), c.getCharacter());
        }
    }

    /**
     * "Tuple class" used by the CharacterSkipper for keeping track of skipped characters and their indexes.
     */
    @Value
    static class IndexedCharacter {
        private final int pos;
        private final char character;
    }

    public static CharacterSkipper of(String text, String allowedChars) {
        return new CharacterSkipper(text, allowedChars);
    }

}
