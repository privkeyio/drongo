package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parse and serialize tests for v2 block headers, driven by block_header_v2.json.
 *
 * The fixture is copied unmodified from src/test/data/block_header_v2.json in the
 * pow_hf_blake2b branch of github.com/luke-jr/bitcoin, at commit 5a3f788e. The wire
 * layout it encodes matches CBlockHeader::SERIALIZE_METHODS in src/primitives/block.h
 * on that branch.
 *
 * Only parsing and serialization are covered here. The hash and proof of work related
 * entries in the fixture (h1, h2, blake2b_1, blake2b_2, mask, block_hash, asic_input)
 * are deliberately not asserted.
 */
public class BlockHeaderV2Test {
    private static final String FIXTURE = "/block_header_v2.json";

    //A v2 header with a wire time of 0xffffff00, a time offset of 0x200, and the time offset flag set
    private static final String WRAPPING_TIME_HEADER_HEX = "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f000ffffffffff001d0df0ad0b44332211efcdab89ffeeddccbbaa9988776655443322110000020000030004000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";

    @Test
    public void testParseFixtureHeaders() throws IOException {
        List<Object> headers = loadHeaders();
        Assertions.assertFalse(headers.isEmpty(), "No headers found in " + FIXTURE);

        for(Object header : headers) {
            Map<String, Object> entry = asObject(header);
            String name = (String)entry.get("name");
            Map<String, Object> fields = asObject(entry.get("fields"));
            byte[] serialized = Utils.hexToBytes((String)entry.get("serialized"));

            Assertions.assertEquals(BlockHeader.V2_LENGTH, serialized.length, name + ": serialized length");

            BlockHeader blockHeader = new BlockHeader(serialized);

            Assertions.assertTrue(blockHeader.isHeaderV2(), name + ": headerV2");
            Assertions.assertEquals(BlockHeader.V2_LENGTH, blockHeader.getLength(), name + ": parsed length");
            Assertions.assertEquals(number(fields, "nVersion"), blockHeader.getVersion(), name + ": version");
            Assertions.assertEquals(0L, blockHeader.getVersion() & BlockHeader.HEADER_V2_FLAG, name + ": version carries bit 31");
            Assertions.assertEquals(fields.get("hashPrevBlock"), blockHeader.getPrevBlockHash().toString(), name + ": prevBlockHash");
            Assertions.assertEquals(fields.get("hashMerkleRoot"), blockHeader.getMerkleRoot().toString(), name + ": merkleRoot");
            Assertions.assertEquals(number(fields, "nBits"), blockHeader.getDifficultyTarget(), name + ": nBits");
            Assertions.assertEquals(number(fields, "nNonce"), blockHeader.getNonce(), name + ": nonce");
            Assertions.assertEquals(number(fields, "m_nonce2"), blockHeader.getNonce2(), name + ": nonce2");
            Assertions.assertEquals(number(fields, "m_nonce3"), blockHeader.getNonce3(), name + ": nonce3");
            Assertions.assertArrayEquals(Utils.hexToBytes((String)fields.get("m_extranonce")), blockHeader.getExtranonce(), name + ": extranonce");
            Assertions.assertEquals(number(fields, "m_time_offset"), blockHeader.getTimeOffset(), name + ": timeOffset");
            Assertions.assertEquals(number(fields, "m_txcount"), blockHeader.getTxCount(), name + ": txCount");
            Assertions.assertEquals(number(fields, "m_flags"), blockHeader.getFlags(), name + ": flags");
            Assertions.assertEquals(number(fields, "m_xor_key_mask_clear_bits"), blockHeader.getXorKeyMaskClearBits(), name + ": xorKeyMaskClearBits");
            Assertions.assertArrayEquals(Utils.hexToBytes((String)fields.get("m_xor_key")), blockHeader.getXorKey(), name + ": xorKey");
            Assertions.assertEquals(number(fields, "m_height"), blockHeader.getHeight(), name + ": height");
            Assertions.assertEquals(fields.get("m_mm_rhs"), blockHeader.getMmRhs().toString(), name + ": mmRhs");

            //The fixture records the block time, while the wire carries it less the offset where the flag is set
            long blockTime = number(fields, "nTime");
            long timeOffset = number(fields, "m_time_offset");
            boolean usesTimeOffset = (number(fields, "m_flags") & BlockHeader.FLAG_USE_TIME_OFFSET) != 0;
            long timeOnWire = blockTime - (usesTimeOffset ? timeOffset : 0);

            Assertions.assertEquals(blockTime, blockHeader.getTime(), name + ": time");
            Assertions.assertEquals(timeOnWire, blockHeader.getTimeOnWire(), name + ": time on wire");
            Assertions.assertEquals(timeOnWire, Utils.readUint32(serialized, 68), name + ": time on wire matches the serialized field");

            Assertions.assertArrayEquals(serialized, blockHeader.bitcoinSerialize(), name + ": round trip");
        }
    }

    @Test
    public void testFixtureCoversTimeOffsetBothWays() throws IOException {
        boolean withOffset = false, withoutOffset = false;
        for(Object header : loadHeaders()) {
            Map<String, Object> fields = asObject(asObject(header).get("fields"));
            if((number(fields, "m_flags") & BlockHeader.FLAG_USE_TIME_OFFSET) != 0) {
                withOffset = true;
            } else {
                withoutOffset = true;
            }
        }

        Assertions.assertTrue(withOffset, "No fixture header sets the time offset flag");
        Assertions.assertTrue(withoutOffset, "No fixture header leaves the time offset flag clear");
    }

    /**
     * The reference implementation reconstructs the time with WrappingAdd and takes it back apart with
     * WrappingSubtract, so both are mod 2^32. This header carries a wire time of 0xffffff00 with an offset
     * of 0x200 and the time offset flag set, making the sum wrap.
     */
    @Test
    public void testTimeReconstructionWrapsModulo32Bits() {
        byte[] serialized = Utils.hexToBytes(WRAPPING_TIME_HEADER_HEX);
        BlockHeader blockHeader = new BlockHeader(serialized);

        Assertions.assertTrue(blockHeader.isHeaderV2());
        Assertions.assertEquals(BlockHeader.V2_LENGTH, blockHeader.getLength());
        Assertions.assertEquals(0x200L, blockHeader.getTimeOffset());
        Assertions.assertEquals(BlockHeader.FLAG_USE_TIME_OFFSET, blockHeader.getFlags());

        //0xffffff00 + 0x200 wraps to 0x100, rather than running on to 0x100000100
        Assertions.assertEquals(0x100L, blockHeader.getTime());

        //And back the other way, 0x100 - 0x200 wraps to 0xffffff00 rather than going negative
        Assertions.assertEquals(0xffffff00L, blockHeader.getTimeOnWire());

        Assertions.assertArrayEquals(serialized, blockHeader.bitcoinSerialize());
    }

    @Test
    public void testVersion1HeaderUnchanged() {
        byte[] serialized = Utils.hexToBytes(BlockHeaderTest.GENESIS_HEADER_HEX);
        BlockHeader blockHeader = new BlockHeader(serialized);

        Assertions.assertFalse(blockHeader.isHeaderV2());
        Assertions.assertEquals(BlockHeader.V1_LENGTH, blockHeader.getLength());
        Assertions.assertEquals(1L, blockHeader.getVersion());
        Assertions.assertEquals(Sha256Hash.ZERO_HASH, blockHeader.getPrevBlockHash());
        Assertions.assertEquals("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", blockHeader.getMerkleRoot().toString());
        Assertions.assertEquals(1231006505L, blockHeader.getTime());
        Assertions.assertEquals(1231006505L, blockHeader.getTimeOnWire());
        Assertions.assertEquals(0x1d00ffffL, blockHeader.getDifficultyTarget());
        Assertions.assertEquals(2083236893L, blockHeader.getNonce());

        assertHeaderV2FieldsNull(blockHeader);
        Assertions.assertArrayEquals(serialized, blockHeader.bitcoinSerialize());
    }

    @Test
    public void testVersion1Block800000HeaderUnchanged() {
        byte[] serialized = Utils.hexToBytes(BlockHeaderTest.BLOCK_800000_HEADER_HEX);
        BlockHeader blockHeader = new BlockHeader(serialized);

        Assertions.assertFalse(blockHeader.isHeaderV2());
        Assertions.assertEquals(BlockHeader.V1_LENGTH, blockHeader.getLength());
        Assertions.assertEquals(0x341d6000L, blockHeader.getVersion());
        Assertions.assertEquals("000000000000000000012117ad9f72c1c0e42227c2d042dca23e6b96bd9fbb55", blockHeader.getPrevBlockHash().toString());
        Assertions.assertEquals("91f01a00530c8c83617190048ea8b0814d506cf24dfdbcf8893f8f0cab7f0855", blockHeader.getMerkleRoot().toString());
        Assertions.assertEquals(1690168629L, blockHeader.getTime());
        Assertions.assertEquals(1690168629L, blockHeader.getTimeOnWire());
        Assertions.assertEquals(0x17053894L, blockHeader.getDifficultyTarget());
        Assertions.assertEquals(106861918L, blockHeader.getNonce());

        assertHeaderV2FieldsNull(blockHeader);
        Assertions.assertArrayEquals(serialized, blockHeader.bitcoinSerialize());
    }

    private void assertHeaderV2FieldsNull(BlockHeader blockHeader) {
        Assertions.assertEquals(0L, blockHeader.getNonce2());
        Assertions.assertEquals(0L, blockHeader.getNonce3());
        Assertions.assertArrayEquals(new byte[16], blockHeader.getExtranonce());
        Assertions.assertEquals(0L, blockHeader.getTimeOffset());
        Assertions.assertEquals(0, blockHeader.getTxCount());
        Assertions.assertEquals(0, blockHeader.getFlags());
        Assertions.assertEquals(0, blockHeader.getXorKeyMaskClearBits());
        Assertions.assertArrayEquals(new byte[16], blockHeader.getXorKey());
        Assertions.assertEquals(0L, blockHeader.getHeight());
        Assertions.assertEquals(Sha256Hash.ZERO_HASH, blockHeader.getMmRhs());
    }

    @Test
    public void testByteArrayGettersReturnCopies() throws IOException {
        Map<String, Object> entry = asObject(loadHeaders().get(0));
        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes((String)entry.get("serialized")));

        byte[] extranonce = blockHeader.getExtranonce();
        byte[] xorKey = blockHeader.getXorKey();
        extranonce[0] ^= 0xff;
        xorKey[0] ^= 0xff;

        Assertions.assertFalse(java.util.Arrays.equals(extranonce, blockHeader.getExtranonce()));
        Assertions.assertFalse(java.util.Arrays.equals(xorKey, blockHeader.getXorKey()));
    }

    private List<Object> loadHeaders() throws IOException {
        try(InputStream inputStream = getClass().getResourceAsStream(FIXTURE)) {
            Assertions.assertNotNull(inputStream, "Missing test resource " + FIXTURE);
            String json = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            return asArray(asObject(new JsonParser(json).parse()).get("headers"));
        }
    }

    private long number(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        Assertions.assertInstanceOf(Long.class, value, "Expected a number for " + key);
        return (Long)value;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> asObject(Object value) {
        Assertions.assertInstanceOf(Map.class, value, "Expected a JSON object");
        return (Map<String, Object>)value;
    }

    @SuppressWarnings("unchecked")
    private List<Object> asArray(Object value) {
        Assertions.assertInstanceOf(List.class, value, "Expected a JSON array");
        return (List<Object>)value;
    }

    /**
     * A minimal JSON reader, sufficient for the fixture, which contains only objects, arrays,
     * strings and integers. Drongo has no JSON dependency and this test does not warrant adding one.
     */
    private static final class JsonParser {
        private final String json;
        private int pos;

        private JsonParser(String json) {
            this.json = json;
        }

        private Object parse() {
            Object value = readValue();
            skipWhitespace();
            if(pos != json.length()) {
                throw new IllegalArgumentException("Trailing content at position " + pos);
            }

            return value;
        }

        private Object readValue() {
            skipWhitespace();
            char c = peek();
            return switch(c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if(peek() == '}') {
                pos++;
                return map;
            }

            while(true) {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                expect(':');
                map.put(key, readValue());
                skipWhitespace();
                char c = next();
                if(c == '}') {
                    return map;
                }
                if(c != ',') {
                    throw new IllegalArgumentException("Expected , or } at position " + (pos - 1));
                }
            }
        }

        private List<Object> readArray() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if(peek() == ']') {
                pos++;
                return list;
            }

            while(true) {
                list.add(readValue());
                skipWhitespace();
                char c = next();
                if(c == ']') {
                    return list;
                }
                if(c != ',') {
                    throw new IllegalArgumentException("Expected , or ] at position " + (pos - 1));
                }
            }
        }

        private String readString() {
            expect('"');
            int start = pos;
            while(peek() != '"') {
                if(peek() == '\\') {
                    throw new IllegalArgumentException("Escapes are not supported at position " + pos);
                }
                pos++;
            }
            String value = json.substring(start, pos);
            pos++;

            return value;
        }

        private Long readNumber() {
            int start = pos;
            while(pos < json.length() && (Character.isDigit(json.charAt(pos)) || json.charAt(pos) == '-')) {
                pos++;
            }
            if(start == pos) {
                throw new IllegalArgumentException("Expected a value at position " + pos);
            }

            return Long.parseLong(json.substring(start, pos));
        }

        private void skipWhitespace() {
            while(pos < json.length() && Character.isWhitespace(json.charAt(pos))) {
                pos++;
            }
        }

        private char peek() {
            if(pos >= json.length()) {
                throw new IllegalArgumentException("Unexpected end of input");
            }

            return json.charAt(pos);
        }

        private char next() {
            char c = peek();
            pos++;

            return c;
        }

        private void expect(char expected) {
            char c = next();
            if(c != expected) {
                throw new IllegalArgumentException("Expected " + expected + " but found " + c + " at position " + (pos - 1));
            }
        }
    }
}
