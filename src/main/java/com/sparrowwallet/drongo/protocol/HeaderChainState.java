package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Validates a contiguous chain of block headers from a trusted anchor, enforcing linkage, the network's required difficulty
 * (including the 2016-block retarget), proof of work, and a median-time-past bound, while accumulating the chain work above the anchor.
 * On test networks (testnet, testnet4, regtest) the required-difficulty rule is relaxed to each header's own target (linkage, own proof of
 * work and median-time-past are still enforced), and chain work is the header count, following Electrum: their min-difficulty and BIP94 rules are not modelled.
 * <p>
 * The median-time-past bound is only enforced once eleven headers have been added, because the eleven headers below the anchor are not
 * available to seed it. The first ten headers above an anchor are therefore accepted with any timestamp, including the header that opens a
 * difficulty period and so supplies the timespan for the retarget 2016 blocks later. Backdating it eases the following period's target,
 * bounded by the fourfold clamp, and costs an attacker a full period mined at the pinned target first.
 */
public class HeaderChainState {
    public static final int RETARGET_INTERVAL = 2016;
    public static final int TARGET_TIMESPAN_SECS = 14 * 24 * 60 * 60;
    private static final int MEDIAN_TIME_SPAN = 11;
    private static final long NO_RETARGET_TIME = -1;

    private final int anchorHeight;
    private int height;
    private Sha256Hash hash;
    private long nextBits;                //the compact target the next header must claim, unless the next header begins a new period
    private long lastRetargetTime = NO_RETARGET_TIME;   //timestamp of the first header in the current difficulty period; set by the first header after the anchor
    private BigInteger chainWork;
    private final Deque<Long> recentTimes = new ArrayDeque<>(MEDIAN_TIME_SPAN);

    /**
     * Anchors the chain at a pinned header: the last header of a difficulty period (height % 2016 == 2015), identified by hash,
     * with the compact target the following period is required to use. Height 0 is exempted for regtest, which has no pinned headers and
     * anchors at its genesis header instead; a height 0 anchor on a network with the full difficulty rules cannot reach a retarget, because
     * genesis is the first header of its period rather than the last and so no period start is ever observed.
     */
    public HeaderChainState(int height, Sha256Hash hash, long nextBits) {
        if((height + 1) % RETARGET_INTERVAL != 0 && height != 0) {
            throw new IllegalArgumentException("Anchor height " + height + " is not the last header of a difficulty period");
        }

        this.anchorHeight = height;
        this.height = height;
        this.hash = hash;
        this.nextBits = nextBits;
        this.chainWork = BigInteger.ZERO;
    }

    public synchronized void add(BlockHeader header) throws VerificationException {
        if(!header.getPrevBlockHash().equals(hash)) {
            throw new VerificationException("Header at height " + (height + 1) + " does not link to the previous header");
        }
        long requiredBits = getRequiredDifficulty(header);
        if(header.getDifficultyTarget() != requiredBits) {
            throw new VerificationException("Header at height " + (height + 1) + " has difficulty target " + Long.toHexString(header.getDifficultyTarget())
                    + " but the chain requires " + Long.toHexString(requiredBits));
        }
        requireExpectedHeaderVersion(height + 1, header);
        if(!header.verifyProofOfWork()) {
            throw new VerificationException("Header at height " + (height + 1) + " does not meet its required proof of work target");
        }
        if(recentTimes.size() == MEDIAN_TIME_SPAN && header.getTime() <= getMedianTimePast()) {
            throw new VerificationException("Header at height " + (height + 1) + " is timestamped at or before the median of the last " + MEDIAN_TIME_SPAN + " headers");
        }

        height++;
        hash = header.getHash();
        if(height % RETARGET_INTERVAL == 0) {
            lastRetargetTime = header.getTime();
        }
        nextBits = header.getDifficultyTarget();
        chainWork = chainWork.add(isFullDifficultyRules() ? getWork(header.getDifficultyTarget()) : BigInteger.ONE);
        if(recentTimes.size() == MEDIAN_TIME_SPAN) {
            recentTimes.removeFirst();
        }
        recentTimes.addLast(header.getTime());
    }

    /**
     * Which proof of work a header at this height is required to carry.
     *
     * The header decides for itself which algorithm its hash is taken with: a v1 header is hashed with SHA256d and a
     * v2 header with BLAKE2b. Nothing else here reads that, so without this check a chain of v1 headers claiming the
     * shifted target the activation height allows would satisfy the difficulty and proof of work rules while being
     * mined with SHA256d, at a target chosen for a network that has none of that hashrate. Checked immediately before
     * the proof of work, since it decides which proof of work the header is claiming to have done.
     *
     * Refused in both directions. A v2 header below the height is no more the chain this follows than a v1 header
     * above it. Networks with no schedule pin nothing and are left alone.
     */
    private static void requireExpectedHeaderVersion(int height, BlockHeader header) throws VerificationException {
        Integer activationHeight = Network.get().getBlake2bHeight();
        if(activationHeight == null) {
            return;
        }

        boolean expectHeaderV2 = height >= activationHeight;
        if(header.isHeaderV2() != expectHeaderV2) {
            throw new VerificationException("Header at height " + height + " is a v" + (header.isHeaderV2() ? "2" : "1")
                    + " header, but the chain requires v" + (expectHeaderV2 ? "2" : "1") + " at that height");
        }
    }

    private long getRequiredDifficulty(BlockHeader header) {
        if(!isFullDifficultyRules()) {
            return header.getDifficultyTarget();    //linkage and the header's own proof of work only; verifyProofOfWork() still enforces powLimit
        }
        if(height == anchorHeight) {
            return nextBits;    //the first header after the anchor is a period boundary whose target is the pinned bits; no period has been observed to retarget from
        }
        long requiredBits;
        if((height + 1) % RETARGET_INTERVAL == 0) {
            if(lastRetargetTime == NO_RETARGET_TIME) {
                throw new VerificationException("Cannot retarget at height " + (height + 1) + ": no difficulty period has started since the anchor at height " + anchorHeight);
            }

            requiredBits = calculateNextWorkRequired(nextBits, lastRetargetTime, getLastTime());
        } else {
            requiredBits = nextBits;
        }

        return applyBlake2bTargetShift(height + 1, requiredBits);
    }

    /**
     * The one off target shift at the activation height, applied after the ordinary rules have produced a target.
     *
     * No hardware mines the new algorithm at the moment it activates, so the block at that height is allowed a much
     * easier target and normal retargeting resumes from it. Applies at exactly one height: a chain that carried the
     * shift forward, or applied it a block early or late, would be refused here as it would be by the network.
     */
    static long applyBlake2bTargetShift(int height, long requiredBits) {
        Integer activationHeight = Network.get().getBlake2bHeight();

        return activationHeight != null && height == activationHeight
                ? Network.get().applyBlake2bTargetShift(requiredBits) : requiredBits;
    }

    /**
     * The compact target required of the period following one that closed at lastBits, having spanned firstTime to lastTime,
     * following Bitcoin Core's CalculateNextWorkRequired. Note Bitcoin's off-by-one: the timespan is measured across 2015 intervals,
     * from the first to the last header of the closing period.
     */
    public static long calculateNextWorkRequired(long lastBits, long firstTime, long lastTime) {
        long timespan = Math.max(TARGET_TIMESPAN_SECS / 4, Math.min((long)TARGET_TIMESPAN_SECS * 4, lastTime - firstTime));
        BigInteger newTarget = Utils.decodeCompactBits(lastBits).multiply(BigInteger.valueOf(timespan)).divide(BigInteger.valueOf(TARGET_TIMESPAN_SECS));
        if(newTarget.compareTo(Network.get().getProofOfWorkLimit()) > 0) {
            newTarget = Network.get().getProofOfWorkLimit();
        }

        return Utils.encodeCompactBits(newTarget);
    }

    /** Mainnet and signet follow the full retarget rules; testnet, testnet4 and regtest do not (see class javadoc). */
    private static boolean isFullDifficultyRules() {
        return Network.get() == Network.MAINNET || Network.get() == Network.SIGNET;
    }

    /** The expected work to produce a block at this compact target, following Bitcoin Core's GetBlockProof: 2^256 / (target + 1). */
    public static BigInteger getWork(long compactBits) {
        return BigInteger.ONE.shiftLeft(256).divide(Utils.decodeCompactBits(compactBits).add(BigInteger.ONE));
    }

    public synchronized int getHeight() {
        return height;
    }

    public synchronized Sha256Hash getHash() {
        return hash;
    }

    /** The work accumulated by the headers added above the anchor, which is comparable across candidate chains only when they share it. */
    public synchronized BigInteger getChainWork() {
        return chainWork;
    }

    private long getLastTime() {
        return recentTimes.getLast();
    }

    private long getMedianTimePast() {
        List<Long> times = new ArrayList<>(recentTimes);
        times.sort(null);

        return times.get(times.size() / 2);
    }

    //No copy(): a rolling state cannot be rewound. A reorg candidate is validated on a throwaway instance re-walked from the anchor to the fork point
}
