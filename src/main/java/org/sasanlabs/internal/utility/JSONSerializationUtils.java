package org.sasanlabs.internal.utility;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.CharacterEscapes;
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;

/**
 * This is the Generic Serialization Utility for the VulnerableApp.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public final class JSONSerializationUtils {

    /**
     * HTML-safe CharacterEscapes for Jackson. Escapes the HTML metacharacters
     * inside JSON string values so that database-sourced content cannot be
     * interpreted as HTML/JavaScript when the JSON response is rendered in a
     * browser context. (CWE-79 mitigation)
     */
    private static final class HtmlSafeCharacterEscapes extends CharacterEscapes {

        private static final long serialVersionUID = 1L;
        private final int[] asciiEscapes;

        HtmlSafeCharacterEscapes() {
            asciiEscapes = CharacterEscapes.standardAsciiEscapesForJSON();
            asciiEscapes['<'] = CharacterEscapes.ESCAPE_CUSTOM;
            asciiEscapes['>'] = CharacterEscapes.ESCAPE_CUSTOM;
            asciiEscapes['&'] = CharacterEscapes.ESCAPE_CUSTOM;
            asciiEscapes['\''] = CharacterEscapes.ESCAPE_CUSTOM;
        }

        @Override
        public int[] getEscapeCodesForAscii() {
            return asciiEscapes;
        }

        @Override
        public SerializableString getEscapeSequence(int ch) {
            switch (ch) {
                case '<':
                    return new SerializedString("\\u003C");
                case '>':
                    return new SerializedString("\\u003E");
                case '&':
                    return new SerializedString("\\u0026");
                case '\'':
                    return new SerializedString("\\u0027");
                default:
                    return null;
            }
        }
    }

    private static final ObjectMapper MAPPER;

    static {
        ObjectMapper m = new ObjectMapper();
        m.getFactory().setCharacterEscapes(new HtmlSafeCharacterEscapes());
        MAPPER = m;
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
