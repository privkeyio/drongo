package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Finding the inputs a wallet can sign derives a key for every derivation an input names, and the PSBT names them.
 *
 * The fingerprint that gates a derivation is in every PSBT handed to a cosigner, so a cosigner can name as many as
 * they like: two hundred inputs naming two thousand each measured nine seconds before this was bounded, on the
 * thread that draws. An input names one derivation per key in its script, so an honest transaction's whole worth is
 * tens of them.
 */
public class SigningNodeFallbackTest {
    private Wallet wallet() throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        wallet.getKeystores().add(Keystore.fromSeed(new DeterministicSeed(
                "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.SINGLE_HD, ScriptType.P2WPKH.getDefaultDerivation()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), null));
        wallet.getNode(KeyPurpose.RECEIVE);
        return wallet;
    }

    /**
     * A PSBT built with one input the wallet holds far beyond its derived range, preceded by however many inputs of
     * named derivations that match nothing.
     */
    private PSBT psbtWithDecoys(Wallet wallet, int decoyInputs, int derivationsEach) throws Exception {
        Keystore keystore = wallet.getKeystores().get(0);
        String fingerprint = keystore.getKeyDerivation().getMasterFingerprint();
        String prefix = keystore.getKeyDerivation().getDerivationPath();

        //Far past anything the wallet has derived, so only the fallback can find it
        WalletNode distant = new WalletNode(wallet, KeyPurpose.RECEIVE, 100_000);
        Script mine = wallet.getScriptType().getOutputScript(PolicyType.SINGLE_HD, keystore.getPubKey(distant));
        Script theirs = ScriptType.P2WPKH.getOutputScript(PolicyType.SINGLE_HD,
                ECKey.fromPrivate(Utils.hexToBytes("99".repeat(32))));

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        for(int i = 0; i <= decoyInputs; i++) {
            transaction.addInput(Sha256Hash.ZERO_HASH, i, new Script(new byte[0]));
        }
        transaction.addOutput(90_000L, theirs);

        PSBT psbt = new PSBT(transaction);
        for(int i = 0; i < decoyInputs; i++) {
            PSBTInput psbtInput = psbt.getPsbtInputs().get(i);
            psbtInput.setWitnessUtxo(new TransactionOutput(null, 100_000L, theirs.getProgram()));
            for(int j = 0; j < derivationsEach; j++) {
                ECKey stranger = ECKey.fromPublicOnly(ECKey.fromPrivate(
                        Utils.hexToBytes("11".repeat(30) + String.format("%04x", j + 1))).getPubKey());
                psbtInput.getDerivedPublicKeys().put(stranger, new KeyDerivation(fingerprint, prefix + "/0/" + j));
            }
        }

        //The wallet's own input, last, only findable through the fallback
        PSBTInput ours = psbt.getPsbtInputs().get(decoyInputs);
        ours.setWitnessUtxo(new TransactionOutput(null, 100_000L, mine.getProgram()));
        ours.getDerivedPublicKeys().put(keystore.getPubKey(distant),
                new KeyDerivation(fingerprint, prefix + "/0/100000"));

        return psbt;
    }

    /** With nothing in the way, the fallback still finds an input beyond the derived range. */
    @Test
    public void the_fallback_finds_an_input_beyond_the_derived_range() throws Exception {
        Wallet wallet = wallet();
        PSBT psbt = psbtWithDecoys(wallet, 0, 0);

        Assertions.assertEquals(1, wallet.getSigningNodes(psbt).size(),
                "the fallback is what finds an input past the range the wallet has derived");
    }

    /** And it stops before a PSBT can spend the session on derivations it named itself. */
    @Test
    public void it_stops_deriving_for_a_psbt_that_names_more_than_a_transaction_could() throws Exception {
        Wallet wallet = wallet();
        //Past the ten thousand this will derive, and nowhere near what an honest transaction names
        PSBT psbt = psbtWithDecoys(wallet, 30, 1000);

        Assertions.assertTrue(wallet.getSigningNodes(psbt).isEmpty(),
                "the decoys named more derivations than this may do, so it has to stop rather than work through them");
    }
}
