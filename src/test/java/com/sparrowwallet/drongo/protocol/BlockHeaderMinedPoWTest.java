package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * v2 headers taken from a node that actually mined them, rather than from a vendored fixture.
 *
 * BlockHeaderPoWHashTest checks every intermediate against src/test/data/block_header_v2.json, which is
 * the right way to localise a divergence but cannot notice when the fixture itself falls behind the
 * implementation it was copied from. That is exactly what happened: h1 commits to the complete version
 * word including the v2 flag, drongo was feeding it the flag stripped, and the fixture of the day
 * agreed with drongo, so the whole suite stayed green while a real chain would not sync.
 *
 * These headers were produced by Bitcoin Knots on a regtest chain with -testactivationheight=blake2b@20,
 * and the expected values are that node's own block hashes. Since the fork hashes a header once and
 * checks the proof of work against that same hash, agreeing with the node here is the property that
 * actually matters, and it cannot be satisfied by a stale fixture.
 */
public class BlockHeaderMinedPoWTest {
    private static final String HEADER_20 = "000000a00b6ae048ff6a63b448cc325a81e22cd304766954f0833e3182dfe8c8cfeca202e44340a302bb650d3050411924e9e83230d3755ee9b2f51509cee40130e8a94f05dd886affff7f2000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000";
    private static final String BLOCK_HASH_20 = "05b020fb60c61a900fb25155693c3a7d9b6c8f578928e55d133b8aaf326b1343";

    private static final String HEADER_25 = "000000a0a67293f4361732ccf34114a438249edb014aa247fc4c4e3780cbc6245f42635a31e2f0189aedd2670150941c0de9e8186ae91b0d54fcd7360277aff4eca8159405dd886affff7f2000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000000000000";
    private static final String BLOCK_HASH_25 = "1c9dbc5abeb14cb14e14fcf6a4e8370b87a131ff338fb7792f5a448fb8781c9c";

    @Test
    public void testMinedHeadersHashAsTheNodeHashedThem() {
        Network.set(Network.REGTEST);

        assertHeader(HEADER_20, BLOCK_HASH_20);
        assertHeader(HEADER_25, BLOCK_HASH_25);
    }

    private void assertHeader(String headerHex, String expectedHash) {
        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(headerHex), 0);
        Assertions.assertTrue(blockHeader.isHeaderV2(), "Header is not a v2 header");
        Assertions.assertEquals(expectedHash, blockHeader.getHash().toString(),
                "Proof of work hash does not match the hash the node mined this header to");
        Assertions.assertTrue(blockHeader.verifyProofOfWork(),
                "A header the node mined and accepted must meet its claimed target here too");
    }

    /**
     * The complete version word carries the v2 flag, and the proof of work commits to it. Clearing the
     * flag has to change the hash, or feeding the stripped word would go unnoticed again.
     */
    @Test
    public void testTheVersionFlagIsCommittedTo() {
        Network.set(Network.REGTEST);

        BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(HEADER_20), 0);
        Assertions.assertEquals(BlockHeader.HEADER_V2_FLAG | blockHeader.getVersion(), blockHeader.getCompleteVersion(),
                "The complete version must carry the v2 flag");
        Assertions.assertNotEquals(blockHeader.getVersion(), blockHeader.getCompleteVersion(),
                "A v2 header's complete version differs from its stripped version, which is the whole hazard");
    }
}
