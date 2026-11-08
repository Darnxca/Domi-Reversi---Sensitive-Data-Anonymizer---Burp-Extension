package com.domireversi.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.BiFunction;
import java.util.function.UnaryOperator;

/**
 * Decodifica di formati binari senza schema (protobuf / gRPC, MessagePack) in un
 * testo leggibile, cosi' l'LLM vede la struttura e il motore puo' anonimizzare i
 * valori: in protobuf come fa {@code protoc --decode_raw} (numeri di campo), in
 * MessagePack come JSON (i nomi dei campi ci sono, quindi valgono le regole per
 * chiave). Nessuna dipendenza esterna. Se i byte non sono del formato atteso
 * restituisce null e il chiamante usa la scansione generica.
 */
public final class BinaryFormats {

    private static final int MAX_DEPTH = 24;
    private static final int MAX_FIELDS = 200_000;

    private BinaryFormats() {
    }

    /** Byte da una stringa in cui ogni carattere e' un byte (0-255); null se non lo e'. */
    public static byte[] latin1(String s) {
        byte[] b = new byte[s.length()];
        for (int i = 0; i < b.length; i++) {
            char c = s.charAt(i);
            if (c > 0xFF) return null;
            b[i] = (byte) c;
        }
        return b;
    }

    // ------------------------------------------------------------- protobuf
    /**
     * Messaggio protobuf in formato testo (numero: valore, messaggi annidati tra
     * graffe). Le stringhe passano per {@code anon} prima di essere scritte.
     */
    public static String protobufText(byte[] data, BiFunction<String, String, String> anon) {
        StringBuilder sb = new StringBuilder();
        int[] budget = {MAX_FIELDS};
        if (!renderMessage(data, 0, data.length, 0, sb, anon, budget)) return null;
        return sb.toString();
    }

    private static boolean renderMessage(byte[] b, int off, int end, int depth, StringBuilder sb,
                                         BiFunction<String, String, String> anon, int[] budget) {
        if (depth > MAX_DEPTH) return false;
        int i = off;
        String prevString = null; // map<string,string>, Struct: la chiave precede il valore
        String ind = "  ".repeat(depth);
        while (i < end) {
            if (--budget[0] < 0) return false;
            long[] tag = varint(b, i, end);
            if (tag == null) return false;
            i = (int) tag[1];
            long field = tag[0] >>> 3;
            int wire = (int) (tag[0] & 7);
            if (field < 1 || field > 536_870_911L) return false;
            switch (wire) {
                case 0: {
                    long[] v = varint(b, i, end);
                    if (v == null) return false;
                    i = (int) v[1];
                    sb.append(ind).append(field).append(": ").append(Long.toUnsignedString(v[0])).append('\n');
                    break;
                }
                case 1: {
                    if (i + 8 > end) return false;
                    long v = 0;
                    for (int k = 7; k >= 0; k--) v = (v << 8) | (b[i + k] & 0xFF);
                    i += 8;
                    sb.append(ind).append(field).append(": 0x").append(Long.toHexString(v)).append(" (fixed64)\n");
                    break;
                }
                case 5: {
                    if (i + 4 > end) return false;
                    int v = (b[i] & 0xFF) | (b[i + 1] & 0xFF) << 8 | (b[i + 2] & 0xFF) << 16 | (b[i + 3] & 0xFF) << 24;
                    i += 4;
                    sb.append(ind).append(field).append(": 0x").append(Integer.toHexString(v)).append(" (fixed32)\n");
                    break;
                }
                case 2: {
                    long[] len = varint(b, i, end);
                    if (len == null) return false;
                    i = (int) len[1];
                    if (len[0] < 0 || len[0] > end - i) return false;
                    int s = i, e = i + (int) len[0];
                    i = e;
                    String text = utf8Text(b, s, e);
                    if (text != null) {
                        sb.append(ind).append(field).append(": \"").append(escape(anon.apply(prevString, text))).append("\"\n");
                        prevString = text;
                        break;
                    }
                    StringBuilder nested = new StringBuilder();
                    int[] snapshot = {budget[0]};
                    if (e > s && renderMessage(b, s, e, depth + 1, nested, anon, snapshot)) {
                        budget[0] = snapshot[0];
                        sb.append(ind).append(field).append(" {\n").append(nested).append(ind).append("}\n");
                    } else {
                        // byte opachi: in base64, cosi' una chiave o un token dentro si vede e si nasconde
                        String b64 = Base64.getEncoder().encodeToString(java.util.Arrays.copyOfRange(b, s, e));
                        sb.append(ind).append(field).append(": bytes(").append(anon.apply(null, b64)).append(")\n");
                    }
                    break;
                }
                default:
                    return false; // gruppi (3/4) deprecati o byte non protobuf
            }
        }
        return i == end;
    }

    /** {valore, nuovo offset} oppure null. */
    private static long[] varint(byte[] b, int i, int end) {
        long v = 0;
        for (int shift = 0; shift < 64 && i < end; shift += 7) {
            int x = b[i++] & 0xFF;
            v |= (long) (x & 0x7F) << shift;
            if ((x & 0x80) == 0) return new long[]{v, i};
        }
        return null;
    }

    /** Testo UTF-8 "da stringa": decodifica valida e tutti caratteri stampabili (tab e a capo ammessi). */
    private static String utf8Text(byte[] b, int s, int e) {
        if (e == s) return "";
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        String t;
        try {
            t = dec.decode(ByteBuffer.wrap(b, s, e - s)).toString();
        } catch (CharacterCodingException ex) {
            return null;
        }
        boolean letterOrDigit = false;
        for (int k = 0; k < t.length(); k++) {
            char c = t.charAt(k);
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') return null;
            if (c == 0x7F) return null;
            if (Character.isLetterOrDigit(c)) letterOrDigit = true;
        }
        return letterOrDigit || t.length() > 2 ? t : null;
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    // ----------------------------------------------------------------- gRPC
    /**
     * Corpo gRPC / gRPC-web: sequenza di frame {flag, lunghezza a 4 byte, messaggio}.
     * Flag 0x80 (gRPC-web) = trailer testuali; flag 0x01 = compresso (gzip).
     */
    public static String grpcText(byte[] data, BiFunction<String, String, String> anonProto, UnaryOperator<String> anonText) {
        StringBuilder sb = new StringBuilder();
        int i = 0, n = 0;
        while (i < data.length) {
            if (i + 5 > data.length) return null;
            int flag = data[i] & 0xFF;
            long len = ((data[i + 1] & 0xFFL) << 24) | ((data[i + 2] & 0xFF) << 16) | ((data[i + 3] & 0xFF) << 8) | (data[i + 4] & 0xFF);
            i += 5;
            if (len > data.length - i) return null;
            byte[] payload = java.util.Arrays.copyOfRange(data, i, i + (int) len);
            i += (int) len;
            n++;
            if ((flag & 0x80) != 0) {
                sb.append("### trailer gRPC-web\n").append(anonText.apply(new String(payload, StandardCharsets.UTF_8)));
                if (sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
                continue;
            }
            if ((flag & 0x01) != 0) {
                payload = gunzip(payload);
                if (payload == null) return null;
            }
            String msg = protobufText(payload, anonProto);
            if (msg == null) return null;
            sb.append("### messaggio ").append(n).append(" (").append(len).append(" byte)\n").append(msg);
        }
        return n == 0 ? null : sb.toString();
    }

    private static byte[] gunzip(byte[] b) {
        try (java.util.zip.GZIPInputStream in = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(b))) {
            return in.readNBytes(20_000_000);
        } catch (java.io.IOException e) {
            return null;
        }
    }

    // ---------------------------------------------------------- MessagePack
    /** MessagePack (anche piu' oggetti di seguito) come JSON, uno per riga; null se non lo e'. */
    public static String msgpackJson(byte[] data) {
        int[] pos = {0};
        StringBuilder sb = new StringBuilder();
        int count = 0;
        try {
            while (pos[0] < data.length) {
                JsonElement el = mpValue(data, pos, 0);
                if (count++ > 0) sb.append('\n');
                sb.append(el.toString());
                if (count > MAX_FIELDS) return null;
            }
        } catch (RuntimeException e) {
            return null;
        }
        return count == 0 ? null : sb.toString();
    }

    private static JsonElement mpValue(byte[] b, int[] p, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalStateException("profondita'");
        int t = u8(b, p);
        if (t <= 0x7F) return new JsonPrimitive(t);
        if (t >= 0xE0) return new JsonPrimitive((byte) t);
        if ((t & 0xF0) == 0x80) return mpMap(b, p, t & 0x0F, depth);
        if ((t & 0xF0) == 0x90) return mpArray(b, p, t & 0x0F, depth);
        if ((t & 0xE0) == 0xA0) return new JsonPrimitive(mpStr(b, p, t & 0x1F));
        switch (t) {
            case 0xC0: return JsonNull.INSTANCE;
            case 0xC2: return new JsonPrimitive(false);
            case 0xC3: return new JsonPrimitive(true);
            case 0xC4: return new JsonPrimitive("base64:" + mpB64(b, p, u8(b, p)));
            case 0xC5: return new JsonPrimitive("base64:" + mpB64(b, p, uN(b, p, 2)));
            case 0xC6: return new JsonPrimitive("base64:" + mpB64(b, p, uN(b, p, 4)));
            case 0xCA: return new JsonPrimitive(Float.intBitsToFloat((int) uN(b, p, 4)));
            case 0xCB: return new JsonPrimitive(Double.longBitsToDouble(uN(b, p, 8)));
            case 0xCC: return new JsonPrimitive(u8(b, p));
            case 0xCD: return new JsonPrimitive(uN(b, p, 2));
            case 0xCE: return new JsonPrimitive(uN(b, p, 4));
            case 0xCF: return new JsonPrimitive(Long.toUnsignedString(uN(b, p, 8)));
            case 0xD0: return new JsonPrimitive((byte) u8(b, p));
            case 0xD1: return new JsonPrimitive((short) uN(b, p, 2));
            case 0xD2: return new JsonPrimitive((int) uN(b, p, 4));
            case 0xD3: return new JsonPrimitive(uN(b, p, 8));
            case 0xD9: return new JsonPrimitive(mpStr(b, p, u8(b, p)));
            case 0xDA: return new JsonPrimitive(mpStr(b, p, (int) uN(b, p, 2)));
            case 0xDB: return new JsonPrimitive(mpStr(b, p, (int) uN(b, p, 4)));
            case 0xDC: return mpArray(b, p, (int) uN(b, p, 2), depth);
            case 0xDD: return mpArray(b, p, (int) uN(b, p, 4), depth);
            case 0xDE: return mpMap(b, p, (int) uN(b, p, 2), depth);
            case 0xDF: return mpMap(b, p, (int) uN(b, p, 4), depth);
            case 0xD4: return mpExt(b, p, 1);
            case 0xD5: return mpExt(b, p, 2);
            case 0xD6: return mpExt(b, p, 4);
            case 0xD7: return mpExt(b, p, 8);
            case 0xD8: return mpExt(b, p, 16);
            case 0xC7: { int n = u8(b, p); return mpExt(b, p, n); }
            case 0xC8: { int n = (int) uN(b, p, 2); return mpExt(b, p, n); }
            case 0xC9: { int n = (int) uN(b, p, 4); return mpExt(b, p, n); }
            default: throw new IllegalStateException("tipo MessagePack non valido");
        }
    }

    private static JsonElement mpMap(byte[] b, int[] p, int n, int depth) {
        if (n < 0 || n > b.length) throw new IllegalStateException("mappa");
        JsonObject o = new JsonObject();
        for (int k = 0; k < n; k++) {
            JsonElement key = mpValue(b, p, depth + 1);
            String name = key.isJsonPrimitive() ? key.getAsString() : key.toString();
            o.add(name, mpValue(b, p, depth + 1));
        }
        return o;
    }

    private static JsonElement mpArray(byte[] b, int[] p, int n, int depth) {
        if (n < 0 || n > b.length) throw new IllegalStateException("array");
        JsonArray a = new JsonArray();
        for (int k = 0; k < n; k++) a.add(mpValue(b, p, depth + 1));
        return a;
    }

    private static JsonElement mpExt(byte[] b, int[] p, int n) {
        int type = (byte) u8(b, p);
        JsonObject o = new JsonObject();
        o.addProperty("$ext", type);
        o.addProperty("data", "base64:" + mpB64(b, p, n));
        return o;
    }

    private static String mpStr(byte[] b, int[] p, int n) {
        if (n < 0 || n > b.length - p[0]) throw new IllegalStateException("stringa");
        String s = new String(b, p[0], n, StandardCharsets.UTF_8);
        p[0] += n;
        return s;
    }

    private static String mpB64(byte[] b, int[] p, long n) {
        if (n < 0 || n > b.length - p[0]) throw new IllegalStateException("bin");
        String s = Base64.getEncoder().encodeToString(java.util.Arrays.copyOfRange(b, p[0], p[0] + (int) n));
        p[0] += (int) n;
        return s;
    }

    private static int u8(byte[] b, int[] p) {
        if (p[0] >= b.length) throw new IllegalStateException("fine dei dati");
        return b[p[0]++] & 0xFF;
    }

    private static long uN(byte[] b, int[] p, int n) {
        if (p[0] + n > b.length) throw new IllegalStateException("fine dei dati");
        long v = 0;
        for (int k = 0; k < n; k++) v = (v << 8) | (b[p[0]++] & 0xFF);
        return v;
    }
}
