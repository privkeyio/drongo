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

    private static final long REGTEST_BITS = 0x207fffffL;

    //Byte offsets in a v2 header: the 80 v1 bytes, then nonce2, nonce3, extranonce, time offset and tx count before the flags,
    //and the mask clear bits and XOR key between the flags and the height
    private static final int V2_FLAGS_OFFSET = 80 + 4 + 4 + 16 + 4 + 2;
    private static final int V2_HEIGHT_OFFSET = V2_FLAGS_OFFSET + 1 + 1 + 16;

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

    @Test
    public void testTheRealActivationHeaderCarriesItsHeightAndNoReservedFlags() throws IOException {
        BlockHeader activation = readHeaders().get(ACTIVATION_HEIGHT - FIRST_HEIGHT);
        Assertions.assertEquals(ACTIVATION_HEIGHT, activation.getHeight());
        Assertions.assertEquals(0, activation.getFlags() & BlockHeader.FLAGS_RESERVED_MASK);
    }

    @Test
    public void testAHeaderCarryingTheWrongHeightIsRefused() throws IOException {
        byte[] bytes = Utils.hexToBytes(readLines().get(ACTIVATION_HEIGHT - FIRST_HEIGHT));
        Utils.uint32ToByteArrayLE(ACTIVATION_HEIGHT + 1, bytes, V2_HEIGHT_OFFSET);
        BlockHeader header = new BlockHeader(bytes);
        Assertions.assertEquals(ACTIVATION_HEIGHT + 1, header.getHeight());

        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> addAtActivation(header));
        Assertions.assertTrue(e.getMessage().contains("carries height " + (ACTIVATION_HEIGHT + 1)), e.getMessage());
    }

    @Test
    public void testAHeaderBelowVersionFourIsRefused() throws IOException {
        byte[] bytes = Utils.hexToBytes(readLines().get(ACTIVATION_HEIGHT - FIRST_HEIGHT));
        Utils.uint32ToByteArrayLE(BlockHeader.HEADER_V2_FLAG | 3, bytes, 0);
        BlockHeader header = new BlockHeader(bytes);
        Assertions.assertTrue(header.isHeaderV2());
        Assertions.assertEquals(3, header.getVersion());

        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> addAtActivation(header));
        Assertions.assertTrue(e.getMessage().contains("below the minimum of 4"), e.getMessage());
    }

    @Test
    public void testAHeaderSettingEitherReservedFlagBitIsRefused() throws IOException {
        for(int bit : new int[] {0x40, 0x80}) {
            byte[] bytes = Utils.hexToBytes(readLines().get(ACTIVATION_HEIGHT - FIRST_HEIGHT));
            bytes[V2_FLAGS_OFFSET] |= (byte)bit;
            BlockHeader header = new BlockHeader(bytes);
            Assertions.assertEquals(bit, header.getFlags() & bit);

            VerificationException e = Assertions.assertThrows(VerificationException.class, () -> addAtActivation(header));
            Assertions.assertTrue(e.getMessage().contains("reserved flag bits"), e.getMessage());
        }
    }

    /**
     * Knots leaves BLAKE2b unscheduled on testnet3 and signet, so a v2 header is never valid there. Knots has no testnet5,
     * so refusing v2 there is this project's own choice rather than a match to the node.
     */
    @Test
    public void testABlake2bHeaderIsRefusedWhereNoScheduleExists() throws IOException {
        for(Network network : new Network[] {Network.TESTNET, Network.SIGNET, Network.TESTNET5}) {
            Network.set(network);
            Assertions.assertNull(network.getBlake2bHeight());

            byte[] bytes = Utils.hexToBytes(readLines().get(ACTIVATION_HEIGHT - FIRST_HEIGHT));
            System.arraycopy(Sha256Hash.wrap(ANCHOR_HASH).getReversedBytes(), 0, bytes, 4, 32);
            Utils.uint32ToByteArrayLE(ANCHOR_BITS, bytes, 72);
            Utils.uint32ToByteArrayLE(ANCHOR_HEIGHT + 1, bytes, V2_HEIGHT_OFFSET);
            BlockHeader header = new BlockHeader(bytes);

            HeaderChainState chainState = new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), ANCHOR_BITS);
            VerificationException e = Assertions.assertThrows(VerificationException.class, () -> chainState.add(header));
            Assertions.assertTrue(e.getMessage().contains("has no BLAKE2b schedule"), network + ": " + e.getMessage());
        }
    }

    /** Regtest picks its own activation height, so its v2 headers are held only to the rules that need no schedule. */
    @Test
    public void testRegtestAcceptsTheRealChainAcrossActivation() throws IOException {
        Network.set(Network.REGTEST);
        List<BlockHeader> headers = readHeaders();

        HeaderChainState chainState = new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), ANCHOR_BITS);
        for(BlockHeader header : headers) {
            chainState.add(header);
        }

        Assertions.assertEquals(FIRST_HEIGHT + headers.size() - 1, chainState.getHeight());
    }

    /**
     * Mined to regtest's proof of work limit, so each header below meets its proof of work and the v2 field rules are
     * the only thing that can refuse it.
     */
    @Test
    public void testMinedRegtestHeadersAreHeldToTheV2FieldRules() throws IOException {
        Network.set(Network.REGTEST);

        BlockHeader valid = mineAboveAnchor(ANCHOR_HEIGHT + 1, 0);
        Assertions.assertTrue(valid.verifyProofOfWork());
        newRegtestChain().add(valid);

        BlockHeader wrongHeight = mineAboveAnchor(ANCHOR_HEIGHT + 2, 0);
        Assertions.assertTrue(wrongHeight.verifyProofOfWork());
        VerificationException e = Assertions.assertThrows(VerificationException.class, () -> newRegtestChain().add(wrongHeight));
        Assertions.assertTrue(e.getMessage().contains("carries height " + (ANCHOR_HEIGHT + 2)), e.getMessage());

        for(int bit : new int[] {0x40, 0x80}) {
            BlockHeader reserved = mineAboveAnchor(ANCHOR_HEIGHT + 1, bit);
            Assertions.assertTrue(reserved.verifyProofOfWork());
            VerificationException f = Assertions.assertThrows(VerificationException.class, () -> newRegtestChain().add(reserved));
            Assertions.assertTrue(f.getMessage().contains("reserved flag bits"), f.getMessage());
        }
    }

    private static HeaderChainState newRegtestChain() {
        return new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), REGTEST_BITS);
    }

    private static BlockHeader mineAboveAnchor(int heightField, int setFlags) throws IOException {
        byte[] bytes = Utils.hexToBytes(readLines().get(ACTIVATION_HEIGHT - FIRST_HEIGHT));
        System.arraycopy(Sha256Hash.wrap(ANCHOR_HASH).getReversedBytes(), 0, bytes, 4, 32);
        Utils.uint32ToByteArrayLE(REGTEST_BITS, bytes, 72);
        Utils.uint32ToByteArrayLE(heightField, bytes, V2_HEIGHT_OFFSET);
        bytes[V2_FLAGS_OFFSET] |= (byte)setFlags;
        for(long nonce = 0; nonce < 1000; nonce++) {
            Utils.uint32ToByteArrayLE(nonce, bytes, 76);
            BlockHeader header = new BlockHeader(bytes);
            if(header.verifyProofOfWork()) {
                return header;
            }
        }

        throw new AssertionError("no nonce met the regtest proof of work limit");
    }

    private static void addAtActivation(BlockHeader header) throws IOException {
        Network.set(Network.MAINNET);
        List<BlockHeader> headers = readHeaders();
        HeaderChainState chainState = new HeaderChainState(ANCHOR_HEIGHT, Sha256Hash.wrap(ANCHOR_HASH), ANCHOR_BITS);
        for(int i = 0; i < ACTIVATION_HEIGHT - FIRST_HEIGHT; i++) {
            chainState.add(headers.get(i));
        }

        chainState.add(header);
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
