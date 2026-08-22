package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * v2 headers taken from the live testnet4 chain, after the BLAKE2b fork activated at height 149460.
 *
 * BlockHeaderMinedPoWTest makes the same argument from a regtest chain the node mined locally. This test
 * makes it from a public chain that already exists, so the expected values are not something this project
 * can regenerate: they are the block hashes testnet4 nodes agreed on, read back from getblockhash. A
 * fixture can be refreshed to match whatever the implementation currently produces, and that is how the
 * stripped version word went unnoticed. These 105 rows cannot be refreshed that way.
 *
 * Every row is compared before the test fails, because the count is the diagnosis. One row disagreeing is
 * an edge case in a single header; all 105 disagreeing is a systematic error in the hash itself.
 */
public class BlockHeaderGroundTruthTest {
    private static final Path GROUND_TRUTH = Path.of(System.getProperty("user.home"), "testnet4", "v2-headers", "ground-truth.tsv");

    private static final int BLAKE2B_ACTIVATION_HEIGHT = 149460;

    @Test
    public void testPoWHashMatchesTestnet4GroundTruth() throws IOException {
        Assumptions.assumeTrue(Files.isReadable(GROUND_TRUTH),
                "No testnet4 ground truth at " + GROUND_TRUTH + ", skipping");

        //The proof of work limit is per network, so reading these headers as anything but testnet4 is meaningless
        Network.set(Network.TESTNET4);

        List<String> lines = Files.readAllLines(GROUND_TRUTH, StandardCharsets.UTF_8);
        List<String> failures = new ArrayList<>();
        int compared = 0;

        for(int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if(line.isEmpty()) {
                continue;
            }

            String[] columns = line.split("\t");
            if(columns.length != 3) {
                throw new IllegalStateException("Expected 3 tab separated columns at " + GROUND_TRUTH.getFileName()
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
            Assertions.fail(failures.size() + " of " + compared + " testnet4 headers at or above height "
                    + BLAKE2B_ACTIVATION_HEIGHT + " do not hash to the value the chain agreed on:"
                    + System.lineSeparator() + String.join(System.lineSeparator(), failures));
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        Network.set(null);
    }
}
