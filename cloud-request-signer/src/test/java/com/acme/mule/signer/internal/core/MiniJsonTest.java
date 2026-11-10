package com.acme.mule.signer.internal.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class MiniJsonTest {

    @Test
    void readsTopLevelStringFields() {
        String json = "{\"token_type\":\"Bearer\", \"expires_in\" : 3599,\n \"access_token\" :  \"eyJ0.abc.def\"}";
        assertEquals("eyJ0.abc.def", MiniJson.stringField(json, "access_token"));
        assertEquals("Bearer", MiniJson.stringField(json, "token_type"));
    }

    @Test
    void absentNonStringOrNullInputGivesNull() {
        assertNull(MiniJson.stringField("{\"a\":\"1\"}", "b"));
        assertNull(MiniJson.stringField("{\"expires_in\":3599}", "expires_in"));
        assertNull(MiniJson.stringField(null, "a"));
        assertNull(MiniJson.stringField("{\"a\":\"unterminated", "a"));
    }

    @Test
    void nameAppearingAsAValueIsSkipped() {
        assertEquals("real", MiniJson.stringField("{\"x\":\"aud\",\"aud\":\"real\"}", "aud"));
    }

    @Test
    void unescapesStringValues() {
        assertEquals("a\"b\\c\ndé/", MiniJson.stringField("{\"k\":\"a\\\"b\\\\c\\nd\\u00e9\\/\"}", "k"));
    }

    @Test
    void quoteEscapesSpecialAndControlCharacters() {
        assertEquals("\"a\\\"b\\\\c\\n\\r\\t\\u0001\"", MiniJson.quote("a\"b\\c\n\r\t\u0001"));
        String round = MiniJson.quote("x\"y\\z\n\u0002");
        assertEquals("x\"y\\z\n\u0002", MiniJson.stringField("{\"k\":" + round + "}", "k"));
    }
}
