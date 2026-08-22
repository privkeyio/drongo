package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * v2 headers read back from the testnet4 chain that activated BLAKE2b at height 149460 under
 * v29.4.1.knots20260508rc1.
 *
 * That chain no longer exists. rc2 moved the testnet4 activation height to 149537, and the chain that
 * followed carries a different block at 149460, so these rows cannot be fetched again from any live node.
 * They are kept here precisely because of that: an expected value no chain can reissue is an expected
 * value nothing can quietly bring into line with a broken implementation.
 *
 * BlockHeaderMinedPoWTest makes the same argument from a regtest chain the node mined locally. This test
 * makes it from a public chain that already existed, so the expected values are not something this project
 * can regenerate: they are the block hashes testnet4 nodes agreed on, read back from getblockhash. A
 * fixture can be refreshed to match whatever the implementation currently produces, and that is how the
 * stripped version word went unnoticed. These 105 rows cannot be refreshed that way, and a future chain
 * cannot supply a replacement, since its own hashes would only ever agree with whatever implementation
 * produced them.
 *
 * Every row is compared before the test fails, because the count is the diagnosis. One row disagreeing is
 * an edge case in a single header; all 105 disagreeing is a systematic error in the hash itself.
 */
public class BlockHeaderGroundTruthTest {
    private static final String GROUND_TRUTH = "/testnet4_v2_headers.tsv";

    private static final int RC1_ACTIVATION_HEIGHT = 149460;

    @Test
    public void testPoWHashMatchesTestnet4GroundTruth() throws IOException {
        //The proof of work limit is per network, so reading these headers as anything but testnet4 is meaningless
        Network.set(Network.TESTNET4);

        List<String> lines = readGroundTruth();
        List<String> failures = new ArrayList<>();
        int compared = 0;

        for(int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if(line.isEmpty()) {
                continue;
            }

            String[] columns = line.split("\t");
            if(columns.length != 3) {
                throw new IllegalStateException("Expected 3 tab separated columns at " + GROUND_TRUTH
                        + " line " + (i + 1) + ", found " + columns.length);
            }

            String height = columns[0];
            String headerHex = columns[1];
            String expectedHash = columns[2];

            compared++;

            //A row that throws is still a row that disagrees, and the remaining rows still need to be counted
            try {
                BlockHeader blockHeader = new BlockHeader(Utils.hexToBytes(headerHex), 0);

                if(!blockHeader.isHeaderV2()) {
                    failures.add("height " + height + ": not parsed as a v2 header");
                    continue;
                }

                String actualHash = blockHeader.getPoWHash().toString();
                if(!expectedHash.equals(actualHash)) {
                    failures.add("height " + height + ": expected " + expectedHash + " but got " + actualHash);
                }
            } catch(Exception e) {
                failures.add("height " + height + ": threw " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        //An empty or unreadable file must not pass as agreement
        Assertions.assertTrue(compared > 0, "No rows read from " + GROUND_TRUTH);

        if(!failures.isEmpty()) {
            Assertions.fail(failures.size() + " of " + compared + " headers from the testnet4 chain that activated at height "
                    + RC1_ACTIVATION_HEIGHT + " do not hash to the value that chain agreed on:"
                    + System.lineSeparator() + String.join(System.lineSeparator(), failures));
        }
    }

    private List<String> readGroundTruth() throws IOException {
        try(InputStream inputStream = getClass().getResourceAsStream(GROUND_TRUTH)) {
            Assertions.assertNotNull(inputStream, "Missing test resource " + GROUND_TRUTH);
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}
