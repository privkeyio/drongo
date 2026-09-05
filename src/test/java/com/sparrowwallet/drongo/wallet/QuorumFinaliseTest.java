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

    private Wallet wallet(ScriptType scriptType) throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(scriptType);
        for(String words : WORDS) {
            wallet.getKeystores().add(Keystore.fromSeed(
                    new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39),
                    PolicyType.MULTI_HD, scriptType.getDefaultDerivation()));
        }
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, scriptType, wallet.getKeystores(), 2));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    /**
     * The marked signer signs last in key order, which is the case that loses. Every signer signs, so there is one
     * more signature than the threshold needs and one has to go.
     */
    @Test
    public void a_quorum_with_a_spare_signature_keeps_the_one_that_opts_in() throws Exception {
        //Every script type a quorum can be spent by. Nulling an entry the map used to have a signature for is new
        //state for all of their scriptSig and witness builders, not only the one this was found on.
        for(ScriptType scriptType : new ScriptType[] {ScriptType.P2WSH, ScriptType.P2SH, ScriptType.P2SH_P2WSH}) {
            assertKeepsTheOptedInSignature(scriptType);
        }
    }

    private void assertKeepsTheOptedInSignature(ScriptType scriptType) throws Exception {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        Wallet wallet = wallet(scriptType);
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
        Script multisigScript = ScriptType.MULTISIG.getOutputScript(2, node.getPubKeys());
        if(scriptType == ScriptType.P2SH) {
            psbtInput.setRedeemScript(multisigScript);
        } else if(scriptType == ScriptType.P2SH_P2WSH) {
            psbtInput.setRedeemScript(ScriptType.P2WSH.getOutputScript(multisigScript));
            psbtInput.setWitnessScript(multisigScript);
        } else {
            psbtInput.setWitnessScript(multisigScript);
        }

        //Everyone signs. Only the one that sorts last opts in, which is the marked device in the case this is about.
        for(int i = 0; i < wallet.getKeystores().size(); i++) {
            psbtInput.setSigHash(i == lastKeystore ? SigHash.fromByte(unifiedAll) : SigHash.ALL);
            Assertions.assertTrue(psbtInput.sign(wallet.getKeystores().get(i).getKey(node)),
                    "every keystore must sign");
        }
        Assertions.assertEquals(3, psbtInput.getPartialSignatures().size(), "all three must have signed");

        wallet.finalise(psbt);

        PSBTInput finalised = psbt.getPsbtInputs().get(0);
        List<TransactionSignature> kept = new ArrayList<>(finalised.getFinalScriptWitness() != null
                ? finalised.getFinalScriptWitness().getSignatures()
                : finalised.getFinalScriptSig().getSignatures());
        Assertions.assertEquals(2, kept.size(), scriptType + " keeps two for a 2 of 3");
        Assertions.assertTrue(kept.stream().anyMatch(signature -> (signature.sighashFlags & SigHash.UNIFIED_FLAG) != 0),
                scriptType + " threw the opted-in signature away and broadcasts unprotected");
    }

    /**
     * The choice at its edges. Whichever way it goes it has to keep exactly the threshold, and it must not depend on
     * any of them opting in: a quorum where none does is the ordinary case and still has to spend.
     */
    @Test
    public void it_keeps_exactly_the_threshold_however_many_opt_in() throws Exception {
        Assertions.assertEquals(0, keptOptedIn(0), "none opted in, so none can be kept");
        Assertions.assertEquals(1, keptOptedIn(1), "the one that opts in is the one worth keeping");
        Assertions.assertEquals(2, keptOptedIn(2), "both of them fit");
        Assertions.assertEquals(2, keptOptedIn(3), "more opt in than there is room for, so it keeps the threshold");
    }

    /** Signs a 2 of 3 with every keystore, the first optingIn of them opting in, and returns how many kept opt in. */
    private int keptOptedIn(int optingIn) throws Exception {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        Wallet wallet = wallet(ScriptType.P2WSH);
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Script spk = wallet.getOutputScript(node);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(90_000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, 100_000L, spk.getProgram()));
        psbtInput.setWitnessScript(ScriptType.MULTISIG.getOutputScript(2, node.getPubKeys()));

        for(int i = 0; i < wallet.getKeystores().size(); i++) {
            psbtInput.setSigHash(i < optingIn ? SigHash.fromByte(unifiedAll) : SigHash.ALL);
            Assertions.assertTrue(psbtInput.sign(wallet.getKeystores().get(i).getKey(node)), "every keystore must sign");
        }

        wallet.finalise(psbt);

        List<TransactionSignature> kept = new ArrayList<>(
                psbt.getPsbtInputs().get(0).getFinalScriptWitness().getSignatures());
        Assertions.assertEquals(2, kept.size(), "a 2 of 3 keeps two whatever they carry");
        return (int)kept.stream().filter(signature -> (signature.sighashFlags & SigHash.UNIFIED_FLAG) != 0).count();
    }

    /** Exactly the threshold signed, so there is no choice to make and nothing may be dropped. */
    @Test
    public void a_quorum_with_no_spare_signature_is_left_alone() throws Exception {
        Wallet wallet = wallet(ScriptType.P2WSH);
        WalletNode node = wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        Script spk = wallet.getOutputScript(node);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(90_000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, 100_000L, spk.getProgram()));
        psbtInput.setWitnessScript(ScriptType.MULTISIG.getOutputScript(2, node.getPubKeys()));
        psbtInput.setSigHash(SigHash.ALL);

        //The two whose keys sort last, so a choice that preferred the earlier ones would be visible
        List<ECKey> ordered = new ArrayList<>(node.getPubKeys());
        ordered.sort(new ECKey.LexicographicECKeyComparator());
        for(Keystore keystore : wallet.getKeystores()) {
            if(!keystore.getPubKey(node).equals(ordered.get(0))) {
                Assertions.assertTrue(psbtInput.sign(keystore.getKey(node)), "the last two must sign");
            }
        }
        Assertions.assertEquals(2, psbtInput.getPartialSignatures().size(), "exactly the threshold must have signed");

        wallet.finalise(psbt);
        Assertions.assertEquals(2,
                psbt.getPsbtInputs().get(0).getFinalScriptWitness().getSignatures().size(),
                "nothing was spare, so nothing may have been dropped");
    }
}
