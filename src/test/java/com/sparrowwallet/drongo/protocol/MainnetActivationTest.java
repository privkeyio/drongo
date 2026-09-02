package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The real mainnet chain across its activation at height 961640, read back from a node that follows it.
 *
 * Every other test of this boundary is synthetic or regtest. These are the headers mainnet actually agreed on, so
 * they are the only ones that pin the difficulty shift against a live target rather than one this project computed,
 * and the only ones that show a 164 byte BLAKE2b header naming an 80 byte SHA256d parent.
 */
public class MainnetActivationTest {
    private static final String HEADERS = "/headers/mainnet-activation.txt";
    private static final int FIRST_HEIGHT = 961632;
    private static final int ACTIVATION_HEIGHT = 961640;

    //The last pinned header, being the close of the difficulty period before activation
    private static final int ANCHOR_HEIGHT = 961631;
    private static final String ANCHOR_HASH = "00000000000000000000807f9dc917442a67910426d79ebb2f8aa2149327ce8a";
    private static final long ANCHOR_BITS = 0x1702353dL;

    //The target mainnet actually required at the activation height, read off the block itself
    private static final long SHIFTED_BITS = 0x1a008d4fL;

    @AfterEach
    public void tearDown() {
        Network.set(null);
    }

    @Test
    public void testTheShiftedTargetMatchesTheOneMainnetRequired() {
        Network.set(Network.MAINNET);
        Assertions.assertEquals(SHIFTED_BITS, Network.get().applyBlake2bTargetShift(ANCHOR_BITS),
                "the shift computed here must equal the target the activation block claims");
        Assertions.assertEquals(SHIFTED_BITS, HeaderChainState.applyBlake2bTargetShift(ACTIVATION_HEIGHT, ANCHOR_BITS));
        Assertions.assertEquals(ANCHOR_BITS, HeaderChainState.applyBlake2bTargetShift(ACTIVATION_HEIGHT - 1, ANCHOR_BITS),
                "the shift applies at exactly one height");
    }

    @Test
    public void testTheRealChainVerifiesAcrossActivation() throws IOException {
        Network.set(Network.MAINNET);
        List<BlockHeader> headers = readHeaders();

        HeaderChainState chainState = new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), ANCHOR_BITS);
        for(BlockHeader header : headers) {
            chainState.add(header);
        }

        Assertions.assertEquals(FIRST_HEIGHT + headers.size() - 1, chainState.getHeight());

        BlockHeader activation = headers.get(ACTIVATION_HEIGHT - FIRST_HEIGHT);
        Assertions.assertTrue(activation.isHeaderV2(), "the activation block is a v2 header");
        Assertions.assertEquals(SHIFTED_BITS, activation.getDifficultyTarget());
        Assertions.assertFalse(headers.get(ACTIVATION_HEIGHT - FIRST_HEIGHT - 1).isHeaderV2(), "its parent is not");
    }

    /**
     * A v1 header claiming the shifted target is the cheap forgery the shift would otherwise invite: the target is
     * eased for hardware that does not yet exist, and SHA256d hashrate that does exist could meet it. Nothing else in
     * the chain rules distinguishes it, so the header version has to be required at the height.
     */
    @Test
    public void testASha256dHeaderIsRefusedAtTheActivationHeight() throws IOException {
        Network.set(Network.MAINNET);
        List<BlockHeader> headers = readHeaders();

        HeaderChainState chainState = new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), ANCHOR_BITS);
        for(int i = 0; i < ACTIVATION_HEIGHT - FIRST_HEIGHT; i++) {
            chainState.add(headers.get(i));
        }

        BlockHeader parent = headers.get(ACTIVATION_HEIGHT - FIRST_HEIGHT - 1);
        BlockHeader forged = new BlockHeader(0x20000000L, parent.getHash(), Sha256Hash.ZERO_HASH, null,
                parent.getTime() + 600, SHIFTED_BITS, 0);
        Assertions.assertFalse(forged.isHeaderV2(), "the forgery is hashed with SHA256d");
        Assertions.assertEquals(SHIFTED_BITS, forged.getDifficultyTarget(), "and claims exactly the target the chain requires");

        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(forged));
        Assertions.assertTrue(e.getMessage().contains("requires v2"), e.getMessage());
    }

    /** The same rule in the other direction: the chain below the height is not the one that carries v2 headers. */
    @Test
    public void testABlake2bHeaderIsRefusedBelowTheActivationHeight() throws IOException {
        Network.set(Network.MAINNET);

        //Built from the real activation header's own bytes with only its parent hash repointed at the anchor, so it is
        //a genuine v2 header presented at a height where v1 is required. The constructor cannot make one: it always
        //produces a v1 header.
        byte[] bytes = Utils.hexToBytes(readLines().get(ACTIVATION_HEIGHT - FIRST_HEIGHT));
        System.arraycopy(Sha256Hash.wrap(ANCHOR_HASH).getReversedBytes(), 0, bytes, 4, 32);
        Utils.uint32ToByteArrayLE(ANCHOR_BITS, bytes, 72);
        BlockHeader premature = new BlockHeader(bytes);
        Assertions.assertTrue(premature.isHeaderV2(), "the header is a v2 header");
        Assertions.assertEquals(Sha256Hash.wrap(ANCHOR_HASH), premature.getPrevBlockHash(), "and links to the anchor");
        Assertions.assertEquals(ANCHOR_BITS, premature.getDifficultyTarget(), "and claims the target the chain requires there");

        HeaderChainState chainState = new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), ANCHOR_BITS);
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(premature));
        Assertions.assertTrue(e.getMessage().contains("requires v1"), e.getMessage());
    }

    private static List<BlockHeader> readHeaders() throws IOException {
        List<BlockHeader> headers = new ArrayList<>();
        for(String line : readLines()) {
            headers.add(new BlockHeader(Utils.hexToBytes(line)));
        }

        return headers;
    }

    private static List<String> readLines() throws IOException {
        try(InputStream inputStream = MainnetActivationTest.class.getResourceAsStream(HEADERS)) {
            Assertions.assertNotNull(inputStream, "Missing test resource " + HEADERS);
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            List<String> lines = new ArrayList<>();
            String line;
            while((line = reader.readLine()) != null) {
                line = line.strip();
                if(!line.isEmpty()) {
                    lines.add(line);
                }
            }
            Assertions.assertFalse(lines.isEmpty(), "no headers read");
            return lines;
        }
    }
}
