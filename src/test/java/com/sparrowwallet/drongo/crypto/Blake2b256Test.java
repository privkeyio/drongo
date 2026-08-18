package com.sparrowwallet.drongo.crypto;

import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test vectors for the empty input and "abc" come from RFC 7693, Appendix A / B
 * (unkeyed BLAKE2b, 256 bit output).
 *
 * The official BLAKE2 KAT (github.com/BLAKE2/BLAKE2, testvectors/blake2-kat.json) only
 * publishes vectors for the full 64 byte BLAKE2b output, not the 32 byte truncated
 * digest_length=32 variant used here. The additional vectors below are therefore generated
 * with the reference Python implementation (hashlib.blake2b(data, digest_size=32)), using
 * the same sequential input convention as the official KAT: an input of length n consists
 * of the bytes 0x00, 0x01, ..., (n - 1).
 */
public class Blake2b256Test {
    @Test
    public void testEmptyInput() {
        byte[] hash = Blake2b256.hash(new byte[0]);
        Assertions.assertArrayEquals(Utils.hexToBytes("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"), hash);
    }

    @Test
    public void testAbc() {
        byte[] hash = Blake2b256.hash("abc".getBytes());
        Assertions.assertArrayEquals(Utils.hexToBytes("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"), hash);
    }

    @Test
    public void testKatVector1Byte() {
        assertKatVector("00", "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314");
    }

    @Test
    public void testKatVector2Bytes() {
        assertKatVector("0001", "01cf79da4945c370c68b265ef70641aaa65eaa8f5953e3900d97724c2c5aa095");
    }

    @Test
    public void testKatVector3Bytes() {
        assertKatVector("000102", "3d8c3d594928271f44aad7a04b177154806867bcf918e1549c0bc16f9da2b09b");
    }

    @Test
    public void testKatVector4Bytes() {
        assertKatVector("00010203", "e1eae5a8adae652ec9af9677346a9d60eced61e3a0a69bfacf518db31f86e36b");
    }

    @Test
    public void testKatVector5Bytes() {
        assertKatVector("0001020304", "663694ac6520bdce7caab1cf3929ffe78cb2fea67a3dfc8559753a9f512a0c85");
    }

    @Test
    public void testKatVector8Bytes() {
        assertKatVector("0001020304050607", "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621");
    }

    @Test
    public void testKatVector16Bytes() {
        assertKatVector("000102030405060708090a0b0c0d0e0f", "c7cb5d1a1a214f1d833a21fe6c7b2420e417c2f220784cbe90072975131bc367");
    }

    @Test
    public void testKatVector32Bytes() {
        assertKatVector("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6");
    }

    private void assertKatVector(String inputHex, String expectedHashHex) {
        byte[] hash = Blake2b256.hash(Utils.hexToBytes(inputHex));
        Assertions.assertArrayEquals(Utils.hexToBytes(expectedHashHex), hash);
    }

    @Test
    public void testStreamingMatchesOneShot() {
        byte[] input = new byte[1000];
        for(int i = 0; i < input.length; i++) {
            input[i] = (byte)(i % 256);
        }

        byte[] oneShot = Blake2b256.hash(input);

        Blake2b256.Digest digest = Blake2b256.newDigest();
        int[] boundaries = new int[] {1, 63, 64, 65};
        int offset = 0;
        for(int boundary : boundaries) {
            digest.update(input, offset, boundary);
            offset += boundary;
        }
        digest.update(input, offset, input.length - offset);
        byte[] streamed = digest.digest();

        Assertions.assertArrayEquals(oneShot, streamed);
    }

    @Test
    public void testOffsetLengthMatchesCopiedSlice() {
        byte[] input = new byte[200];
        for(int i = 0; i < input.length; i++) {
            input[i] = (byte)(i * 7);
        }

        int offset = 37;
        int length = 91;

        byte[] slice = new byte[length];
        System.arraycopy(input, offset, slice, 0, length);

        byte[] hashOfSlice = Blake2b256.hash(slice);
        byte[] hashOfRange = Blake2b256.hash(input, offset, length);

        Assertions.assertArrayEquals(hashOfSlice, hashOfRange);
    }
}
