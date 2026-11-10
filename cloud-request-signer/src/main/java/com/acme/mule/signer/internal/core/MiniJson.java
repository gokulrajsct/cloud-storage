package com.acme.mule.signer.internal.core;

/**
 * The two JSON jobs the connector has (reading string fields of Entra ID's flat token response and
 * writing a JWT's flat header/claims) without pulling a JSON library into every Mule app.
 */
final class MiniJson {

    private MiniJson() {
    }

    /** Value of a top-level string field, or null when absent / not a string. */
    static String stringField(String json, String name) {
        if (json == null) {
            return null;
        }
        String needle = quote(name);
        int i = json.indexOf(needle);
        while (i >= 0) {
            int j = skipWs(json, i + needle.length());
            if (j < json.length() && json.charAt(j) == ':') {
                j = skipWs(json, j + 1);
                if (j < json.length() && json.charAt(j) == '"') {
                    return readString(json, j + 1);
                }
                return null;
            }
            i = json.indexOf(needle, i + 1);
        }
        return null;
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    private static int skipWs(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    private static String readString(String s, int i) {
        StringBuilder sb = new StringBuilder();
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') {
                return sb.toString();
            }
            if (c != '\\' || i >= s.length()) {
                sb.append(c);
                continue;
            }
            char e = s.charAt(i++);
            switch (e) {
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'u':
                    if (i + 4 <= s.length()) {
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    break;
                default: sb.append(e);
            }
        }
        return null; // unterminated
    }
}
