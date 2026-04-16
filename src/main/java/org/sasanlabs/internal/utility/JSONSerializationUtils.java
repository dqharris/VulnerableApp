package org.sasanlabs.internal.utility;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.CharacterEscapes;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;

/**
 * This is the Generic Serialization Utility for the VulnerableApp.
 *
 * <p>The ObjectMapper is configured with HTML-safe character escaping to prevent
 * stored XSS payloads in database fields from being rendered as HTML.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public final class JSONSerializationUtils {

    /**
     * HTML-safe ObjectMapper: escapes {@code <}, {@code >}, {@code &}, and {@code '}
     * in JSON string values to their Unicode escape equivalents (\u003c, etc.).
     * This prevents stored XSS payloads from executing even if a frontend inserts
     * JSON values directly into the DOM.
     */
    private static final ObjectMapper MAPPER;

    static {
        JsonFactory factory = new JsonFactory();
        factory.setCharacterEscapes(new CharacterEscapes() {
            private static final long serialVersionUID = 1L;
            private final int[] asciiEscapes;
            {
                asciiEscapes = standardAsciiEscapesForJSON();
                asciiEscapes['<'] = CharacterEscapes.ESCAPE_STANDARD;
                asciiEscapes['>'] = CharacterEscapes.ESCAPE_STANDARD;
                asciiEscapes['&'] = CharacterEscapes.ESCAPE_STANDARD;
                asciiEscapes['\''] = CharacterEscapes.ESCAPE_STANDARD;
            }
            @Override
            public int[] getEscapeCodesForAscii() { return asciiEscapes; }
            @Override
            public SerializableString getEscapeSequence(int ch) { return null; }
        });
        MAPPER = new ObjectMapper(factory);
    }

    private JSONSerializationUtils() {}

    public static <T> String serialize(T object) throws JsonProcessingException {
        return MAPPER.writeValueAsString(object);
    }

    public static <T> String serializeWithPrettyPrintJSON(T object) throws JsonProcessingException {
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(object);
    }

    public static <T> T deserialize(InputStream in, TypeReference<T> typeReference)
            throws JsonParseException, JsonMappingException, IOException {
        return MAPPER.readValue(in, typeReference);
    }

    public static <T> T deserialize(InputStream in, Class<T> clazz)
            throws JsonParseException, JsonMappingException, IOException {
        return MAPPER.readValue(in, clazz);
    }
}
