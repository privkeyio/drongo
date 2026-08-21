package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Stage by stage tests for the v2 (BLAKE2b) proof of work hash, driven by block_header_v2.json.
 *
 * The fixture is copied unmodified from src/test/data/block_header_v2.json in the pow_hf_blake2b
 * branch of github.com/luke-jr/bitcoin, at commit 6ba00bc6, and records every intermediate of
 * CBlockHeader::GetHash() in src/primitives/block.cpp on that branch. Asserting each stage means a
 * future divergence names the stage that broke rather than only the final hash.
 *
 * Byte order is the main hazard here, since drongo's Sha256Hash holds display order while Core's
 * uint256 holds wire order, and getReversedBytes()/ReversedBytes() therefore mean opposite things.
 * Every order below was established by reimplementing the pipeline against the fixture rather than
 * inferred, and holds for all five headers:
 *
 *   xor_key_hash, mask, h1, h2, blake2b_1, blake2b_2, asic_input   fixture hex is WIRE order
 *   block_hash                                                     fixture hex is DISPLAY order
 *
 * The final value is reversed relative to the others because GetHash() writes the closing XOR out
 * backwards (final_hash[31 - i] = hash[i] ^ mask[i]), so the fixture's block_hash lines up with
 * Sha256Hash.toString(). The intermediates are raw SHA256/BLAKE2b output and are hex encoded as is,
 * so they are compared as byte[] against Utils.hexToBytes without any reversal.
 */
public class BlockHeaderPoWHashTest {
    private static final String FIXTURE = "/block_header_v2.json";

    /**
     * A v2 header that tells the two hashes apart: it meets its target under BLAKE2b but misses it under
     * SHA256d, so it only verifies if verifyProofOfWork() uses the former.
     *
     * Produced offline from the first fixture header by setting nBits to 0x2000ffff, a target of roughly
     * 2^248 that lets about one hash in 256 through while staying well inside the regtest proof of work
     * limit, then grinding nonce2 until both conditions held. nonce2 = 135 was the first to qualify.
     */
    private static final String DISCRIMINATING_HEADER_HEX = "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff00200df0ad0b87000000efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";
    private static final long DISCRIMINATING_NBITS = 0x2000ffffL;
    private static final String DISCRIMINATING_POW_HASH = "00c99031e59e5fc5e70e149025f6c8acd5ac774e882a9e2bf3e0ce82d4a017e8";
    private static final String DISCRIMINATING_SHA256D_HASH = "9a1c4a7367e691f9db7fd3cd070791149699f503ae4ba7f6a176828b155e963d";

    /**
     * SHA256(tag || tag || m_xor_key), where m_xor_key is fed in wire order.
     * Fixture is wire order; the Java side is expected to return the raw 32 byte digest.
     */
    @Test
    public void testXorKeyHash() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "xor_key_hash"), blockHeader.getPoWXorKeyHash(),
                    name(header) + ": xor_key_hash mismatch");
        }
    }

    /**
     * The XOR mask, all zeroes when the key is null, otherwise SHA256(tag || tag || m_xor_key) with
     * the leading m_xor_key_mask_clear_bits cleared. Fixture is wire order, as is the expected return.
     */
    @Test
    public void testXorKeyMask() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "mask"), blockHeader.getPoWXorKeyMask(),
                    name(header) + ": mask mismatch");
        }
    }

    /**
     * h1, the tagged hash over the fields a mining machine never sees, in this order:
     * nVersion, prevblock (display order), height, merkle root (wire order), time on wire, a reserved
     * zero byte, nBits, txcount as a uint32, flags, clear bits, and the xor key hash. 119 bytes.
     * Fixture is wire order, as is the expected return.
     */
    @Test
    public void testHeaderHash1() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "h1"), blockHeader.getPoWHash1(),
                    name(header) + ": h1 mismatch");
        }
    }

    /**
     * h2, the merge-mining hook: tagged hash over h1, 32 zero bytes, then m_mm_rhs in wire order.
     * Fixture is wire order, as is the expected return.
     */
    @Test
    public void testMergeMiningHash() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "h2"), blockHeader.getPoWHash2(),
                    name(header) + ": h2 mismatch");
        }
    }

    /**
     * The first BLAKE2b round, over the 52 byte Sv1 stream: a zero uint32, h2, then the extranonce
     * in wire order. Fixture is wire order, as is the expected return.
     */
    @Test
    public void testBlake2bRound1() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "blake2b_1"), blockHeader.getPoWBlake2bRound1(),
                    name(header) + ": blake2b_1 mismatch");
        }
    }

    /**
     * The ASIC profile, which is the low two bits of m_flags and selects the field ordering below.
     */
    @Test
    public void testAsicProfile() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertEquals(number(header, "asic_profile"), blockHeader.getAsicProfile(),
                    name(header) + ": asic_profile mismatch");
        }
    }

    /**
     * The stream fed to the second BLAKE2b round, whose layout and length depend on the profile:
     *   0: prevblock_hidden with its first 6 bytes cleared, nonce, nonce2, time offset, nonce3, round 1   (80 bytes)
     *   1: nonce, nonce2, nonce3, time offset, round 1, h2                                                (80 bytes)
     *   2: 48 zero bytes, h2, nonce, nonce2, time offset, nonce3, round 1                                (128 bytes)
     *   3: as profile 2 with a further 32 zero bytes in front                                            (160 bytes)
     * Fixture is wire order, as is the expected return. All four profiles appear across the five headers.
     */
    @Test
    public void testAsicInput() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "asic_input"), blockHeader.getPoWAsicInput(),
                    name(header) + ": asic_input mismatch");
        }
    }

    /**
     * The second BLAKE2b round, over the ASIC input. Fixture is wire order, as is the expected return.
     */
    @Test
    public void testBlake2bRound2() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertArrayEquals(hex(header, "blake2b_2"), blockHeader.getPoWBlake2bRound2(),
                    name(header) + ": blake2b_2 mismatch");
        }
    }

    /**
     * The final hash, round 2 XORed with the mask and written out reversed. Unlike every stage above,
     * the fixture value is in display order, so it is compared against Sha256Hash.toString() rather
     * than as raw bytes.
     */
    @Test
    public void testBlockHash() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            BlockHeader blockHeader = parseHeader(header);
            Assertions.assertEquals(header.get("block_hash"), blockHeader.getPoWHash().toString(),
                    name(header) + ": block_hash mismatch");
        }
    }

    /**
     * The final hash is round 2 XORed bytewise with the mask, which the fixture lets us check
     * independently of the implementation. This one asserts only fixture self consistency, so it
     * passes today and pins the relationship the implementation has to reproduce.
     */
    @Test
    public void testBlockHashIsRound2XoredWithMask() throws IOException {
        for(Map<String, Object> header : loadHeaders()) {
            byte[] round2 = hex(header, "blake2b_2");
            byte[] mask = hex(header, "mask");
            byte[] expected = hex(header, "block_hash");

            byte[] xored = new byte[round2.length];
            for(int i = 0; i < round2.length; i++) {
                xored[i] = (byte)(round2[i] ^ mask[i]);
            }

            Assertions.assertArrayEquals(expected, xored, name(header) + ": block_hash is not blake2b_2 xor mask");
        }
    }

    /**
     * A v1 header takes the historical SHA256d path, so its proof of work hash is just its block hash.
     */
    @Test
    public void testVersion1UsesSha256d() {
        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(BlockHeaderTest.GENESIS_HEADER_HEX));

        Assertions.assertFalse(blockHeader.isHeaderV2());
        Assertions.assertEquals(blockHeader.getHash(), blockHeader.getPoWHash());
    }

    /**
     * A header that passes its target under the BLAKE2b hash and fails it under SHA256d, so it only verifies
     * if the proof of work is measured against the right one. A fixture header fails under either hash and
     * so would not tell the two apart.
     */
    @Test
    public void testVersion2VerifiesAgainstPoWHash() {
        Network.set(Network.REGTEST);

        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(DISCRIMINATING_HEADER_HEX));
        BigInteger target = blockHeader.getDifficultyTargetAsInteger();

        Assertions.assertTrue(blockHeader.isHeaderV2());
        Assertions.assertEquals(DISCRIMINATING_NBITS, blockHeader.getDifficultyTarget());
        Assertions.assertTrue(target.compareTo(Network.get().getProofOfWorkLimit()) <= 0, "Target is easier than the regtest limit");

        //The BLAKE2b hash is under the target, while the SHA256d hash is over it
        Assertions.assertEquals(DISCRIMINATING_POW_HASH, blockHeader.getPoWHash().toString());
        Assertions.assertEquals(DISCRIMINATING_SHA256D_HASH, blockHeader.getHash().toString());
        Assertions.assertTrue(blockHeader.getPoWHash().toBigInteger().compareTo(target) <= 0, "BLAKE2b hash should meet the target");
        Assertions.assertTrue(blockHeader.getHash().toBigInteger().compareTo(target) > 0, "SHA256d hash should miss the target");

        Assertions.assertTrue(blockHeader.verifyProofOfWork());
    }

    /**
     * A v1 header still verifies against SHA256d, since getPoWHash() delegates to getHash() for it.
     */
    @Test
    public void testVersion1StillVerifies() {
        Network.set(Network.MAINNET);

        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(BlockHeaderTest.GENESIS_HEADER_HEX));

        Assertions.assertFalse(blockHeader.isHeaderV2());
        Assertions.assertTrue(blockHeader.verifyProofOfWork());
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }

    private BlockHeader parseHeader(Map<String, Object> header) {
        return new BlockHeader(Utils.hexToBytes((String)header.get("serialized")));
    }

    private String name(Map<String, Object> header) {
        return (String)header.get("name");
    }

    private byte[] hex(Map<String, Object> header, String key) {
        Object value = header.get(key);
        Assertions.assertInstanceOf(String.class, value, "Expected a hex string for " + key);
        return Utils.hexToBytes((String)value);
    }

    private long number(Map<String, Object> header, String key) {
        Object value = header.get(key);
        Assertions.assertInstanceOf(Long.class, value, "Expected a number for " + key);
        return (Long)value;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> loadHeaders() throws IOException {
        try(InputStream inputStream = getClass().getResourceAsStream(FIXTURE)) {
            Assertions.assertNotNull(inputStream, "Missing test resource " + FIXTURE);
            String json = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            Object headers = ((Map<String, Object>)new JsonParser(json).parse()).get("headers");
            Assertions.assertInstanceOf(List.class, headers, "Expected a JSON array of headers");

            List<Map<String, Object>> list = new ArrayList<>();
            for(Object header : (List<Object>)headers) {
                Assertions.assertInstanceOf(Map.class, header, "Expected a JSON object per header");
                list.add((Map<String, Object>)header);
            }
            Assertions.assertFalse(list.isEmpty(), "No headers found in " + FIXTURE);

            return list;
        }
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
