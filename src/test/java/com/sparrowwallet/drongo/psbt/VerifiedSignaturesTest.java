package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptChunk;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Telling a signature from a push that merely looks like one.
 *
 * Any 64 or 65 byte push decodes as a Schnorr signature whose hash type is its last byte, and nothing in that decode is
 * checked, so reading hash types off a signed input reports whatever those bytes happen to say. A control block, an
 * uncompressed public key and a run of miner data in a coinbase are all that shape. The signature is the thing that can
 * be checked, and this checks it.
 */
public class VerifiedSignaturesTest {
    private static final String PRIVATE_KEY = "11".repeat(32);
    private static final long VALUE = 100_000_000L;

    private ECKey key() {
        return ECKey.fromPrivate(Utils.hexToBytes(PRIVATE_KEY));
    }

    /** What a caller vouches for: the key this fixture's wallet would hold. */
    private List<ECKey> trusted() {
        return List.of(ECKey.fromPublicOnly(ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, key())));
    }

    /**
     * One P2WPKH input signed for real, with the hash type asked for.
     */
    private PSBTInput signedInput(byte sigHashType) {
        ECKey outputKey = ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, key());
        Script spk = ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, key());

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(VALUE - 10_000, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, VALUE, spk.getProgram()));
        psbtInput.setSigHash(SigHash.fromByte(sigHashType));
        psbtInput.sign(outputKey);

        return psbtInput;
    }

    /** The 65 byte push that a control block, an uncompressed key or miner data all look like. */
    private byte[] junk(byte last) {
        byte[] push = new byte[65];
        Arrays.fill(push, (byte)0x11);
        push[64] = last;
        return push;
    }

    @Test
    public void a_real_signature_verifies_and_keeps_its_hash_type() {
        PSBTInput psbtInput = signedInput(SigHash.ALL.byteValue());

        List<TransactionSignature> verified = psbtInput.getVerifiedSignatures(trusted());
        Assertions.assertEquals(1, verified.size(), "the signature this input really carries did not verify");
        Assertions.assertEquals(SigHash.ALL.byteValue(), verified.get(0).sighashFlags);
    }

    @Test
    public void an_opted_in_signature_is_read_as_opted_in() {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        PSBTInput psbtInput = signedInput(unifiedAll);

        List<TransactionSignature> verified = psbtInput.getVerifiedSignatures(trusted());
        Assertions.assertEquals(1, verified.size());
        Assertions.assertEquals(unifiedAll, verified.get(0).sighashFlags);
        Assertions.assertNotEquals(0, verified.get(0).sighashFlags & SigHash.UNIFIED_FLAG);
    }

    /**
     * The case this exists for. The witness carries a real signature that does not opt in, beside a push that is not a
     * signature at all and ends in a byte that says it opts in. Read without checking, the input reports an opt-in it
     * does not have.
     */
    @Test
    public void a_push_that_only_looks_like_a_signature_is_not_counted() {
        PSBTInput psbtInput = signedInput(SigHash.ALL.byteValue());
        ECKey outputKey = ScriptType.P2WPKH.getOutputKey(PolicyType.SINGLE_HD, key());
        TransactionSignature real = psbtInput.getPartialSignature(ECKey.fromPublicOnly(outputKey));

        List<byte[]> pushes = new ArrayList<>();
        pushes.add(real.encodeToBitcoin());
        pushes.add(outputKey.getPubKey());
        pushes.add(junk((byte)0x21));
        psbtInput.setFinalScriptWitness(new TransactionWitness(null, pushes));

        int looksLikeOptIn = 0;
        for(TransactionSignature signature : psbtInput.getSignatures()) {
            if((signature.sighashFlags & SigHash.UNIFIED_FLAG) != 0) {
                looksLikeOptIn++;
            }
        }
        Assertions.assertEquals(1, looksLikeOptIn, "the unchecked reading must be fooled, or this proves nothing");

        List<TransactionSignature> verified = psbtInput.getVerifiedSignatures(trusted());
        Assertions.assertEquals(1, verified.size(), "only the signature that verifies belongs here");
        Assertions.assertEquals(SigHash.ALL.byteValue(), verified.get(0).sighashFlags);
        for(TransactionSignature signature : verified) {
            Assertions.assertEquals(0, signature.sighashFlags & SigHash.UNIFIED_FLAG,
                    "a push that is not a signature was counted as an opt-in");
        }
    }

    /**
     * A finalised multisig, which is the shape that hides its keys.
     *
     * Finalising clears the witness script and the partial signatures, so the quorum's keys are left only inside the
     * script the final witness carries. An input read through its own fields alone finds no key here, verifies nothing,
     * and reports a fully opted-in quorum as carrying no protection at all.
     */
    @Test
    public void a_finalised_multisig_still_finds_its_keys() {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        ECKey first = ECKey.fromPrivate(Utils.hexToBytes("11".repeat(32)));
        ECKey second = ECKey.fromPrivate(Utils.hexToBytes("22".repeat(32)));
        Script witnessScript = ScriptType.MULTISIG.getOutputScript(2, List.of(first, second));
        Script spk = ScriptType.P2WSH.getOutputScript(witnessScript);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(VALUE - 10_000, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, VALUE, spk.getProgram()));
        psbtInput.setWitnessScript(witnessScript);
        psbtInput.setSigHash(SigHash.fromByte(unifiedAll));
        psbtInput.sign(first);
        psbtInput.sign(second);

        TransactionSignature firstSignature = psbtInput.getPartialSignature(ECKey.fromPublicOnly(first));
        TransactionSignature secondSignature = psbtInput.getPartialSignature(ECKey.fromPublicOnly(second));
        Assertions.assertNotNull(firstSignature, "the fixture must be signed by both keys");
        Assertions.assertNotNull(secondSignature, "the fixture must be signed by both keys");

        List<byte[]> pushes = new ArrayList<>();
        pushes.add(new byte[0]);
        pushes.add(firstSignature.encodeToBitcoin());
        pushes.add(secondSignature.encodeToBitcoin());
        pushes.add(witnessScript.getProgram());

        psbtInput.clearNonFinalFields();
        psbtInput.setFinalScriptWitness(new TransactionWitness(null, pushes));
        Assertions.assertNull(psbtInput.getWitnessScript(), "finalising must have cleared what this has to recover");

        List<TransactionSignature> verified = psbtInput.getVerifiedSignatures(
                List.of(ECKey.fromPublicOnly(first), ECKey.fromPublicOnly(second)));
        Assertions.assertEquals(2, verified.size(), "the quorum's signatures were not found once finalised");
        for(TransactionSignature signature : verified) {
            Assertions.assertEquals(unifiedAll, signature.sighashFlags);
        }
    }

    /**
     * An input carrying more to check than any script could spend is not checked at all. The work is a product of the
     * signatures and the keys, both of which an input chooses, so it has a ceiling; answering nothing past it keeps the
     * promise that a caller must treat what is missing as absent.
     */
    @Test
    public void an_input_asking_for_more_checks_than_a_script_could_need_is_refused() {
        PSBTInput psbtInput = signedInput(SigHash.ALL.byteValue());

        List<ECKey> manyKeys = new ArrayList<>();
        for(int i = 0; i < 40; i++) {
            manyKeys.add(ECKey.fromPrivate(Utils.hexToBytes(String.format("%064x", i + 2))));
        }

        List<byte[]> pushes = new ArrayList<>();
        for(int i = 0; i < 40; i++) {
            pushes.add(junk((byte)0x21));
        }
        psbtInput.setFinalScriptWitness(new TransactionWitness(null, pushes));

        Assertions.assertTrue(psbtInput.getVerifiedSignatures(manyKeys).isEmpty(),
                "an input past the ceiling must answer nothing rather than spend the time");
    }

    /**
     * A signature by a key the caller does not vouch for, which is the shape a hostile PSBT takes.
     *
     * Every key an input carries is written by whoever wrote the input, so a stranger can sign the message for any hash
     * type they like with a key of their own and name it in the input. Checking against those keys would answer "did
     * someone sign something" and read as a protection this transaction does not have.
     */
    @Test
    public void a_signature_by_a_key_the_caller_does_not_vouch_for_is_not_counted() {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        PSBTInput psbtInput = signedInput(SigHash.ALL.byteValue());

        ECKey stranger = new ECKey();
        psbtInput.setSigHash(SigHash.fromByte(unifiedAll));
        psbtInput.sign(stranger);
        Assertions.assertEquals(2, psbtInput.getPartialSignatures().size(), "the input must carry the stranger's signature");

        List<TransactionSignature> verified = psbtInput.getVerifiedSignatures(trusted());
        Assertions.assertEquals(1, verified.size(), "only the key the caller vouches for counts");
        Assertions.assertEquals(SigHash.ALL.byteValue(), verified.get(0).sighashFlags,
                "the stranger's opted-in signature was counted");
    }

    /**
     * An input with no spent output cannot have its message built, so nothing on it can be checked. Reporting nothing is
     * what makes a caller treat the protection as absent rather than as present.
     */
    @Test
    public void nothing_verifies_where_there_is_no_message_to_verify_against() {
        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        transaction.addOutput(VALUE, ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD, key()));

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setFinalScriptWitness(new TransactionWitness(null, List.of(junk((byte)0x21), junk((byte)0x21))));

        Assertions.assertTrue(psbtInput.getVerifiedSignatures(trusted()).isEmpty());
    }
}
