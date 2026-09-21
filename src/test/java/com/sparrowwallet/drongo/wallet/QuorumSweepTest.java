package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The choice held to its rules over every quorum shape, rather than over the one it was found on.
 *
 * Every test elsewhere here is a 2 of 3, so the cap on how many opted-in signatures are kept has only ever been asked
 * for two, and an opt-in scattered through a larger quorum has never been tried at all. This walks every threshold of
 * every quorum up to five signers, and within each one every pattern of who opts in, checking the things that have to
 * be true whatever the shape: the threshold is met exactly, what is kept stays in the order of the keys and holds no
 * signature twice, as many opt in as there is room for, and a quorum where none does keeps exactly what key order
 * kept. That last one is every multisig wallet that has never heard of this, so it is the one a regression would be
 * felt on most widely.
 */
public class QuorumSweepTest {
    private static final byte UNIFIED_ALL = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
    private static final int MAX_SIGNERS = 5;

    private final Map<Integer, List<Keystore>> keystores = new HashMap<>();

    @Test
    public void every_quorum_shape_keeps_the_threshold_in_key_order_preferring_the_opt_in() throws Exception {
        int checked = 0;
        for(int signers = 2; signers <= MAX_SIGNERS; signers++) {
            for(int threshold = 1; threshold <= signers; threshold++) {
                for(int optIn = 0; optIn < (1 << signers); optIn++) {
                    assertShape(signers, threshold, optIn);
                    checked++;
                }
            }
        }
        Assertions.assertEquals(256, checked, "the sweep must cover every shape it claims to");
    }

    private void assertShape(int signers, int threshold, int optInMask) throws Exception {
        String shape = threshold + " of " + signers + ", opting in " + Integer.toBinaryString(optInMask);

        Wallet wallet = wallet(signers, threshold);
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Script spk = wallet.getOutputScript(node);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(90_000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, 100_000L, spk.getProgram()));
        psbtInput.setWitnessScript(ScriptType.MULTISIG.getOutputScript(threshold, node.getPubKeys()));

        List<ECKey> ordered = new ArrayList<>(node.getPubKeys());
        ordered.sort(new ECKey.LexicographicECKeyComparator());
        Set<ECKey> optsIn = new HashSet<>();
        for(int i = 0; i < signers; i++) {
            if((optInMask & (1 << i)) != 0) {
                optsIn.add(ordered.get(i));
            }
        }

        for(Keystore keystore : wallet.getKeystores()) {
            psbtInput.setSigHash(optsIn.contains(keystore.getPubKey(node))
                    ? SigHash.fromByte(UNIFIED_ALL) : SigHash.ALL);
            Assertions.assertTrue(psbtInput.sign(keystore.getKey(node)), shape + ": every keystore must sign");
        }

        List<TransactionSignature> inKeyOrder = new ArrayList<>();
        for(ECKey pubKey : ordered) {
            inKeyOrder.add(psbtInput.getPartialSignature(pubKey));
        }

        wallet.finalise(psbt);
        List<TransactionSignature> kept = new ArrayList<>(
                psbt.getPsbtInputs().get(0).getFinalScriptWitness().getSignatures());

        Assertions.assertEquals(threshold, kept.size(), shape + ": the threshold has to be met exactly");
        Assertions.assertEquals(kept.size(), kept.stream().distinct().count(),
                shape + ": a signature kept twice cannot be matched twice and will not spend");

        int at = 0;
        for(TransactionSignature signature : kept) {
            while(at < inKeyOrder.size() && !inKeyOrder.get(at).equals(signature)) {
                at++;
            }
            Assertions.assertTrue(at < inKeyOrder.size(), shape + ": the kept signatures are not in the order of the keys");
            at++;
        }

        long keptOptIn = kept.stream().filter(s -> (s.sighashFlags & SigHash.UNIFIED_FLAG) != 0).count();
        Assertions.assertEquals(Math.min(Integer.bitCount(optInMask), threshold), keptOptIn,
                shape + ": as many opt in as there is room for, and no more");

        if(optInMask == 0) {
            Assertions.assertEquals(inKeyOrder.subList(0, threshold), kept,
                    shape + ": with nothing to prefer this has to keep exactly what key order kept");
        }
    }

    private Wallet wallet(int signers, int threshold) throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.getKeystores().addAll(keystores(signers));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), threshold));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    /** Derived once per quorum size, since seeding a keystore is the slow part of this. */
    private List<Keystore> keystores(int signers) throws Exception {
        List<Keystore> existing = keystores.get(signers);
        if(existing != null) {
            return existing;
        }

        List<Keystore> derived = new ArrayList<>();
        for(int i = 0; i < signers; i++) {
            byte[] entropy = new byte[16];
            entropy[0] = (byte)(i + 1);
            entropy[15] = (byte)(signers * 16 + i);
            String words = String.join(" ", Bip39MnemonicCode.INSTANCE.toMnemonic(entropy));
            derived.add(Keystore.fromSeed(new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39),
                    PolicyType.MULTI_HD, ScriptType.P2WSH.getDefaultDerivation()));
        }
        keystores.put(signers, derived);
        return derived;
    }
}
