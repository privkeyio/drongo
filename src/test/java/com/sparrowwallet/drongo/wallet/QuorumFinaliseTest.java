package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
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
import java.util.List;

/**
 * Which signatures a quorum keeps when more signers signed than it needs.
 *
 * A 2 of 3 whose marked device signs third has three signatures and room for two. They are chosen in key order, so
 * the opted-in one can be the one dropped, and the transaction broadcasts carrying no replay protection at all,
 * having had it. The label is right about the result and the wallet threw the protection away.
 */
public class QuorumFinaliseTest {
    private static final String[] WORDS = {
            "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor",
            "sell arrive brand fluid cousin twin trap bar hen fine bicycle rack",
            "quantum lens tag pencil kingdom obey noise pigeon oyster shoulder ordinary tilt"};

    private Wallet wallet() throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        for(String words : WORDS) {
            wallet.getKeystores().add(Keystore.fromSeed(
                    new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39),
                    PolicyType.MULTI_HD, ScriptType.P2WSH.getDefaultDerivation()));
        }
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    /**
     * The marked signer signs last in key order, which is the case that loses. Every signer signs, so there is one
     * more signature than the threshold needs and one has to go.
     */
    @Test
    public void a_quorum_with_a_spare_signature_keeps_the_one_that_opts_in() throws Exception {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        Wallet wallet = wallet();
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Script spk = wallet.getOutputScript(node);

        //Whichever keystore's key sorts last is the one a key ordered choice drops
        List<ECKey> ordered = new ArrayList<>(node.getPubKeys());
        ordered.sort(new ECKey.LexicographicECKeyComparator());
        ECKey last = ordered.get(ordered.size() - 1);
        int lastKeystore = -1;
        for(int i = 0; i < wallet.getKeystores().size(); i++) {
            if(wallet.getKeystores().get(i).getPubKey(node).equals(last)) {
                lastKeystore = i;
            }
        }
        Assertions.assertTrue(lastKeystore >= 0, "the fixture must find the keystore that sorts last");

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(90_000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, 100_000L, spk.getProgram()));
        psbtInput.setWitnessScript(ScriptType.MULTISIG.getOutputScript(2, node.getPubKeys()));

        //Everyone signs. Only the one that sorts last opts in, which is the marked device in the case this is about.
        for(int i = 0; i < wallet.getKeystores().size(); i++) {
            psbtInput.setSigHash(i == lastKeystore ? SigHash.fromByte(unifiedAll) : SigHash.ALL);
            Assertions.assertTrue(psbtInput.sign(wallet.getKeystores().get(i).getKey(node)),
                    "every keystore must sign");
        }
        Assertions.assertEquals(3, psbtInput.getPartialSignatures().size(), "all three must have signed");

        wallet.finalise(psbt);

        List<TransactionSignature> kept = new ArrayList<>(
                psbt.getPsbtInputs().get(0).getFinalScriptWitness().getSignatures());
        Assertions.assertEquals(2, kept.size(), "a 2 of 3 keeps two");
        Assertions.assertTrue(kept.stream().anyMatch(signature -> (signature.sighashFlags & SigHash.UNIFIED_FLAG) != 0),
                "the opted-in signature was thrown away and the transaction broadcasts unprotected");
    }
}
