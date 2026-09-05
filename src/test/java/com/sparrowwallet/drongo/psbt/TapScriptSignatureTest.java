package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A taproot script path signature is kept rather than dropped at the door.
 *
 * It was falling through to the unrecognized branch, which logs and discards. An input carrying only these then arrived
 * with no partial signatures, no key path signature and nothing finalised, which is indistinguishable from an input
 * nothing has signed. A wallet asking "has anything signed this" got no, and a label that reports what a transaction
 * will be republished the file's own declaration as though it had been checked.
 *
 * They are not verified here. The leaf script that would check them travels in PSBT_IN_TAP_LEAF_SCRIPT, which this does
 * not parse, so what they establish is presence and nothing more, which is exactly what the caller needs to stop
 * reading an unsigned answer off a signed transaction.
 */
public class TapScriptSignatureTest {
    private static final String X_ONLY_KEY = "aa".repeat(32);
    private static final String LEAF_HASH = "bb".repeat(32);

    private byte[] signature(byte sigHashType) {
        byte[] signature = new byte[65];
        Arrays.fill(signature, (byte)0x33);
        signature[64] = sigHashType;
        return signature;
    }

    private PSBTEntry tapScriptEntry(byte[] signature) {
        byte[] keyData = Utils.hexToBytes(X_ONLY_KEY + LEAF_HASH);
        byte[] key = new byte[1 + keyData.length];
        key[0] = PSBTInput.PSBT_IN_TAP_SCRIPT_SIG;
        System.arraycopy(keyData, 0, key, 1, keyData.length);

        return new PSBTEntry(key, PSBTInput.PSBT_IN_TAP_SCRIPT_SIG, keyData, signature);
    }

    private PSBTInput inputFrom(List<PSBTEntry> entries) throws Exception {
        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));

        return new PSBTInput(new PSBT(transaction), entries, 0);
    }

    @Test
    public void a_script_path_signature_is_read_and_kept() throws Exception {
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        PSBTInput psbtInput = inputFrom(List.of(tapScriptEntry(signature(unifiedAll))));

        Assertions.assertEquals(1, psbtInput.getTapScriptSignatures().size(),
                "an input carrying only these read as one nothing had signed");
        Assertions.assertEquals(unifiedAll,
                psbtInput.getTapScriptSignatures().get(X_ONLY_KEY + LEAF_HASH).sighashFlags,
                "the hash type is the last byte, which is the byte the whole question turns on");
    }

    /** And survives being written back out, so keeping it does not come at the cost of dropping it on the way out. */
    @Test
    public void it_survives_a_round_trip() throws Exception {
        byte[] signature = signature(SigHash.ALL.byteValue());
        PSBTInput psbtInput = inputFrom(List.of(tapScriptEntry(signature)));

        List<PSBTEntry> written = new ArrayList<>();
        for(PSBTEntry entry : psbtInput.getInputEntries(0)) {
            if(entry.getKeyType() == PSBTInput.PSBT_IN_TAP_SCRIPT_SIG) {
                written.add(entry);
            }
        }
        Assertions.assertEquals(1, written.size(), "it was parsed and then not written back");
        Assertions.assertArrayEquals(signature, written.get(0).getData());
        Assertions.assertEquals(X_ONLY_KEY + LEAF_HASH, Utils.bytesToHex(written.get(0).getKeyData()));

        Assertions.assertEquals(1, inputFrom(written).getTapScriptSignatures().size(),
                "and reads back the same on the other side");
    }

    /** Key data that is not a public key and a leaf hash is refused rather than stored under a nonsense key. */
    @Test
    public void a_malformed_key_is_refused() {
        byte[] keyData = new byte[7];
        byte[] key = new byte[1 + keyData.length];
        key[0] = PSBTInput.PSBT_IN_TAP_SCRIPT_SIG;

        Assertions.assertThrows(PSBTParseException.class,
                () -> inputFrom(List.of(new PSBTEntry(key, PSBTInput.PSBT_IN_TAP_SCRIPT_SIG, keyData, signature(SigHash.ALL.byteValue())))));
    }

    /** Cleared with the rest of the pre-finalisation state, since a finalised input carries its witness instead. */
    @Test
    public void it_is_cleared_when_the_input_is_finalised() throws Exception {
        PSBTInput psbtInput = inputFrom(List.of(tapScriptEntry(signature(SigHash.ALL.byteValue()))));
        psbtInput.clearNonFinalFields();

        Assertions.assertTrue(psbtInput.getTapScriptSignatures().isEmpty());
    }
}
