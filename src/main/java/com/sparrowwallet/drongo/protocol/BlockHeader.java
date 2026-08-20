package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.Blake2b256;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

import static com.sparrowwallet.drongo.Utils.uint16ToByteStreamLE;
import static com.sparrowwallet.drongo.Utils.uint32ToByteStreamLE;

public class BlockHeader extends Message {
    /** Bit 31 of the version word marks a v2 header. It is never carried in the version field itself. */
    public static final long HEADER_V2_FLAG = 0x80000000L;

    /** When this flag is set, the time on the wire is the block time less the time offset. */
    public static final int FLAG_USE_TIME_OFFSET = 0x04;

    public static final int V1_LENGTH = 80;
    public static final int V2_LENGTH = 164;

    private static final int EXTRANONCE_LENGTH = 16;
    private static final int XOR_KEY_LENGTH = 16;

    //The reference implementation pads the proof of work streams with uint128 zeroes. That is the same width
    //as the extranonce, but unrelated to it, so it has its own constant here.
    private static final int POW_PADDING_LENGTH = 16;

    private static final String TAG_XOR_KEY = "Bitcoin block hash PoW XOR key";
    private static final String TAG_XOR_MASK = "Bitcoin block hash PoW XOR mask";
    private static final String TAG_PREVBLOCK_HIDDEN = "Bitcoin prevblock header, hashed";
    private static final String TAG_HEADER_1 = "Bitcoin block header 1";
    private static final String TAG_MERGE_MINING = "Merge-mining hook";

    private boolean headerV2;
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot, witnessRoot;
    //As in the reference implementation, this holds the actual block time, not the (possibly offset) time on the wire
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;

    //Header v2 fields, all null for a v1 header. Note these cannot be initialized here, since the
    //superclass constructor parses the payload before this class' field initializers would run.
    private long nonce2;
    private long nonce3;
    private byte[] extranonce;
    private long timeOffset;
    private int txCount;
    private int flags;
    private int xorKeyMaskClearBits;
    private byte[] xorKey;
    private long height;
    private Sha256Hash mmRhs;

    public BlockHeader(byte[] rawheader) {
        super(rawheader, 0);
    }

    public BlockHeader(byte[] blockdata, int offset) {
        super(blockdata, offset);
    }

    public BlockHeader(long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, Sha256Hash witnessRoot, long time, long difficultyTarget, long nonce) {
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.witnessRoot = witnessRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
        setHeaderV2FieldsNull();
    }

    @Override
    protected void parse() throws ProtocolException {
        long versionWord = readUint32();
        headerV2 = (versionWord & HEADER_V2_FLAG) != 0;
        version = versionWord & ~HEADER_V2_FLAG;
        prevBlockHash = readHash();
        merkleRoot = readHash();
        long timeOnWire = readUint32();
        difficultyTarget = readUint32();
        nonce = readUint32();

        if(headerV2) {
            nonce2 = readUint32();
            nonce3 = readUint32();
            extranonce = readReversedBytes(EXTRANONCE_LENGTH);
            timeOffset = readUint32();
            txCount = readUint16();
            flags = readByte();
            xorKeyMaskClearBits = readByte();
            xorKey = readReversedBytes(XOR_KEY_LENGTH);
            height = readUint32();
            mmRhs = readHash();
        } else {
            setHeaderV2FieldsNull();
        }

        //The wire carries the time less the offset when the flag is set, so add it back to get the block time
        time = (timeOnWire + (usesTimeOffset() ? timeOffset : 0)) & 0xFFFFFFFFL;

        length = cursor - offset;
    }

    private void setHeaderV2FieldsNull() {
        nonce2 = 0;
        nonce3 = 0;
        extranonce = new byte[EXTRANONCE_LENGTH];
        timeOffset = 0;
        txCount = 0;
        flags = 0;
        xorKeyMaskClearBits = 0;
        xorKey = new byte[XOR_KEY_LENGTH];
        height = 0;
        mmRhs = Sha256Hash.ZERO_HASH;
    }

    private int readUint16() throws ProtocolException {
        try {
            int u = Utils.readUint16(payload, cursor);
            cursor += 2;
            return u;
        } catch(ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    private int readByte() throws ProtocolException {
        return readBytes(1)[0] & 0xff;
    }

    /** Reads a blob that, like a hash, is written to the wire in reverse of its display order. */
    private byte[] readReversedBytes(int length) throws ProtocolException {
        return Utils.reverseBytes(readBytes(length));
    }

    /** Whether bit 31 of the version word was set, indicating the additional v2 fields are present. */
    public boolean isHeaderV2() {
        return headerV2;
    }

    public long getVersion() {
        return version;
    }

    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    public Sha256Hash getMerkleRoot() {
        return merkleRoot;
    }

    public Sha256Hash getWitnessRoot() {
        return witnessRoot;
    }

    /** The block time, with the time offset already added back where the header uses one. */
    public long getTime() {
        return time;
    }

    /** The time as it appears on the wire, which is the block time less the offset where the header uses one. */
    public long getTimeOnWire() {
        return (time - (usesTimeOffset() ? timeOffset : 0)) & 0xFFFFFFFFL;
    }

    private boolean usesTimeOffset() {
        return (flags & FLAG_USE_TIME_OFFSET) != 0;
    }

    public Date getTimeAsDate() {
        return new Date(time * 1000);
    }

    public long getDifficultyTarget() {
        return difficultyTarget;
    }

    public long getNonce() {
        return nonce;
    }

    public long getNonce2() {
        return nonce2;
    }

    public long getNonce3() {
        return nonce3;
    }

    public byte[] getExtranonce() {
        return extranonce.clone();
    }

    public long getTimeOffset() {
        return timeOffset;
    }

    public int getTxCount() {
        return txCount;
    }

    public int getFlags() {
        return flags;
    }

    public int getXorKeyMaskClearBits() {
        return xorKeyMaskClearBits;
    }

    public byte[] getXorKey() {
        return xorKey.clone();
    }

    public long getHeight() {
        return height;
    }

    public Sha256Hash getMmRhs() {
        return mmRhs;
    }

    public Sha256Hash getHash() {
        return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bitcoinSerialize()));
    }

    /**
     * The ASIC profile, being the low two bits of the flags. It selects the field ordering fed to the
     * second BLAKE2b round.
     */
    public int getAsicProfile() {
        return flags & 3;
    }

    /**
     * The tagged hash of the XOR key. A pooled miner only learns the key itself on finding a block, so
     * the header commits to this instead.
     */
    public byte[] getPoWXorKeyHash() {
        return Utils.taggedHash(TAG_XOR_KEY, getXorKeyOnWire());
    }

    /**
     * The mask the final hash is XORed with, which is all zeroes where no XOR key is set. Otherwise it is
     * the tagged hash of the key with its leading xorKeyMaskClearBits cleared.
     */
    public byte[] getPoWXorKeyMask() {
        byte[] xorKeyOnWire = getXorKeyOnWire();
        if(isNull(xorKeyOnWire)) {
            return new byte[Sha256Hash.LENGTH];
        }

        byte[] mask = Utils.taggedHash(TAG_XOR_MASK, xorKeyOnWire);
        int clearBytes = xorKeyMaskClearBits / 8;
        for(int i = 0; i < clearBytes; i++) {
            mask[i] = 0;
        }
        mask[clearBytes] &= (byte)(0xff >>> (xorKeyMaskClearBits % 8));

        return mask;
    }

    /**
     * The first tagged hash, covering the fields a mining machine never sees. Keeping them out of the
     * mined data means a hasher cannot brick itself at some future block version, time or difficulty.
     */
    public byte[] getPoWHash1() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            uint32ToByteStreamLE(version, outputStream);
            //The previous block hash is the one hash fed in display rather than wire order
            outputStream.write(prevBlockHash.getBytes());
            uint32ToByteStreamLE(height, outputStream);
            outputStream.write(merkleRoot.getReversedBytes());
            uint32ToByteStreamLE(getTimeOnWire(), outputStream);
            outputStream.write(0); //Reserved for extended 40 bit time
            uint32ToByteStreamLE(difficultyTarget, outputStream);
            uint32ToByteStreamLE(txCount, outputStream);
            outputStream.write(flags);
            outputStream.write(xorKeyMaskClearBits);
            outputStream.write(getPoWXorKeyHash());

            return Utils.taggedHash(TAG_HEADER_1, outputStream.toByteArray());
        } catch(IOException e) {
            //can't happen
        }

        return null;
    }

    /**
     * The second tagged hash, providing a hook for future merge mining.
     */
    public byte[] getPoWHash2() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(getPoWHash1());
            outputStream.write(new byte[2 * POW_PADDING_LENGTH]);
            outputStream.write(mmRhs.getReversedBytes());

            return Utils.taggedHash(TAG_MERGE_MINING, outputStream.toByteArray());
        } catch(IOException e) {
            //can't happen
        }

        return null;
    }

    /**
     * The first BLAKE2b round, over the stream sent to mining machines over Sv1. The leading zeroes are the
     * remainder of the Sv1 coinb1, and the extranonce follows it.
     */
    public byte[] getPoWBlake2bRound1() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            uint32ToByteStreamLE(0, outputStream);
            outputStream.write(getPoWHash2());
            outputStream.write(getExtranonceOnWire());

            return Blake2b256.hash(outputStream.toByteArray());
        } catch(IOException e) {
            //can't happen
        }

        return null;
    }

    /**
     * The stream fed to the second BLAKE2b round, which the mining hardware is presumed to see. Its layout
     * depends on the ASIC profile, with profile 1 ordering the nonces differently to the others.
     */
    public byte[] getPoWAsicInput() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] blake2bRound1 = getPoWBlake2bRound1();

            switch(getAsicProfile()) {
                case 0 -> {
                    //The first six bytes of the hidden previous block hash are cleared
                    byte[] prevBlockHidden = Utils.taggedHash(TAG_PREVBLOCK_HIDDEN, prevBlockHash.getBytes());
                    for(int i = 0; i < 6; i++) {
                        prevBlockHidden[i] = 0;
                    }
                    outputStream.write(prevBlockHidden);
                    writeNonces(outputStream);
                    outputStream.write(blake2bRound1);
                }
                case 1 -> {
                    uint32ToByteStreamLE(nonce, outputStream);
                    uint32ToByteStreamLE(nonce2, outputStream);
                    uint32ToByteStreamLE(nonce3, outputStream);
                    uint32ToByteStreamLE(timeOffset, outputStream);
                    outputStream.write(blake2bRound1);
                    outputStream.write(getPoWHash2());
                }
                default -> {
                    if(getAsicProfile() == 3) {
                        outputStream.write(new byte[2 * POW_PADDING_LENGTH]);
                    }
                    outputStream.write(new byte[3 * POW_PADDING_LENGTH]);
                    outputStream.write(getPoWHash2());
                    writeNonces(outputStream);
                    outputStream.write(blake2bRound1);
                }
            }

            return outputStream.toByteArray();
        } catch(IOException e) {
            //can't happen
        }

        return null;
    }

    private void writeNonces(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(nonce, stream);
        uint32ToByteStreamLE(nonce2, stream);
        uint32ToByteStreamLE(timeOffset, stream);
        uint32ToByteStreamLE(nonce3, stream);
    }

    /**
     * The second BLAKE2b round, over the ASIC input.
     */
    public byte[] getPoWBlake2bRound2() {
        return Blake2b256.hash(getPoWAsicInput());
    }

    /**
     * The hash the proof of work is measured against. A v1 header uses the historical SHA256d algorithm,
     * while a v2 header runs the BLAKE2b pipeline and XORs the result with the key mask.
     *
     * Note the reference implementation writes the closing XOR out backwards, so its result is in wire
     * order. Wrapping the XOR directly gives the same hash here, since Sha256Hash holds display order.
     */
    public Sha256Hash getPoWHash() {
        if(!headerV2) {
            return getHash();
        }

        byte[] blake2bRound2 = getPoWBlake2bRound2();
        byte[] mask = getPoWXorKeyMask();

        byte[] hash = new byte[Sha256Hash.LENGTH];
        for(int i = 0; i < hash.length; i++) {
            hash[i] = (byte)(blake2bRound2[i] ^ mask[i]);
        }

        return Sha256Hash.wrap(hash);
    }

    private byte[] getExtranonceOnWire() {
        return Utils.reverseBytes(extranonce);
    }

    private byte[] getXorKeyOnWire() {
        return Utils.reverseBytes(xorKey);
    }

    private static boolean isNull(byte[] bytes) {
        for(byte b : bytes) {
            if(b != 0) {
                return false;
            }
        }

        return true;
    }

    public BigInteger getDifficultyTargetAsInteger() {
        return Utils.decodeCompactBits(difficultyTarget);
    }

    /**
     * Checks the proof of work hash meets the header's own claimed difficulty target, and that the target does
     * not exceed the network proof of work limit. A v1 header is measured against its SHA256d hash as before,
     * while a v2 header is measured against the BLAKE2b hash its proof of work is actually done over.
     */
    public boolean verifyProofOfWork() {
        BigInteger target = getDifficultyTargetAsInteger();
        if(target.signum() <= 0 || target.compareTo(Network.get().getProofOfWorkLimit()) > 0) {
            return false;
        }

        return getPoWHash().toBigInteger().compareTo(target) <= 0;
    }

    public byte[] bitcoinSerialize() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            bitcoinSerializeToStream(outputStream);
            return outputStream.toByteArray();
        } catch (IOException e) {
            //can't happen
        }

        return null;
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE((headerV2 ? HEADER_V2_FLAG : 0L) | version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(merkleRoot.getReversedBytes());
        uint32ToByteStreamLE(getTimeOnWire(), stream);
        uint32ToByteStreamLE(difficultyTarget, stream);
        uint32ToByteStreamLE(nonce, stream);

        if(headerV2) {
            uint32ToByteStreamLE(nonce2, stream);
            uint32ToByteStreamLE(nonce3, stream);
            stream.write(Utils.reverseBytes(extranonce));
            uint32ToByteStreamLE(timeOffset, stream);
            uint16ToByteStreamLE(txCount, stream);
            stream.write(flags);
            stream.write(xorKeyMaskClearBits);
            stream.write(Utils.reverseBytes(xorKey));
            uint32ToByteStreamLE(height, stream);
            stream.write(mmRhs.getReversedBytes());
        }
    }
}
