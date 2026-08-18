package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;

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
        time = timeOnWire + (usesTimeOffset() ? timeOffset : 0);

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
        return time - (usesTimeOffset() ? timeOffset : 0);
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

    public BigInteger getDifficultyTargetAsInteger() {
        return Utils.decodeCompactBits(difficultyTarget);
    }

    /** Checks the header hash meets its own claimed difficulty target, and that the target does not exceed the network proof of work limit. */
    public boolean verifyProofOfWork() {
        BigInteger target = getDifficultyTargetAsInteger();
        if(target.signum() <= 0 || target.compareTo(Network.get().getProofOfWorkLimit()) > 0) {
            return false;
        }

        return getHash().toBigInteger().compareTo(target) <= 0;
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
