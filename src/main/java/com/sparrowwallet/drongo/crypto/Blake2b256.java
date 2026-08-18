package com.sparrowwallet.drongo.crypto;

import org.bouncycastle.crypto.digests.Blake2bDigest;

/**
 * Unkeyed BLAKE2b-256 (RFC 7693), no salt, no personalization, producing a 32 byte output.
 * A thin wrapper over BouncyCastle's {@link Blake2bDigest}.
 */
public class Blake2b256 {
    public static final int LENGTH = 32;

    /**
     * Calculates the unkeyed BLAKE2b-256 hash of the given bytes.
     *
     * @param input the bytes to hash
     * @return the 32 byte hash
     */
    public static byte[] hash(byte[] input) {
        return hash(input, 0, input.length);
    }

    /**
     * Calculates the unkeyed BLAKE2b-256 hash of the given byte range.
     *
     * @param input the array containing the bytes to hash
     * @param offset the offset within the array of the bytes to hash
     * @param length the number of bytes to hash
     * @return the 32 byte hash
     */
    public static byte[] hash(byte[] input, int offset, int length) {
        Digest digest = newDigest();
        digest.update(input, offset, length);
        return digest.digest();
    }

    /**
     * Returns a new streaming BLAKE2b-256 digest instance.
     *
     * @return a new digest instance
     */
    public static Digest newDigest() {
        return new Digest();
    }

    public static class Digest {
        private final Blake2bDigest digest;

        private Digest() {
            this.digest = new Blake2bDigest(256);
        }

        public void update(byte[] input) {
            update(input, 0, input.length);
        }

        public void update(byte[] input, int offset, int length) {
            digest.update(input, offset, length);
        }

        /**
         * Completes the hash and returns the 32 byte digest.
         * This instance is reset and may be reused for a new hash.
         *
         * @return the 32 byte hash
         */
        public byte[] digest() {
            byte[] out = new byte[LENGTH];
            digest.doFinal(out, 0);
            return out;
        }
    }
}
