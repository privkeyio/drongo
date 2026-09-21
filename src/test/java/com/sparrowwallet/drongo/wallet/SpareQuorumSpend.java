package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
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
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;

import java.util.ArrayList;
import java.util.List;

/**
 * Whether what a quorum keeps actually spends, asked of a node rather than of ourselves.
 *
 * QuorumFinaliseTest asserts which signatures survive finalising, which is the choice this fork makes. It cannot say
 * that the result is a transaction consensus will accept, and for a witness assembled by dropping entries from a map
 * that is the part worth being sure of. This prints the address to fund and the raw transaction that comes out, so a
 * regtest node with the hardfork active answers it.
 *
 *   addresses                                  -> SCRIPTTYPE ADDRESS, one line each
 *   spend SCRIPTTYPE TXID VOUT VALUE OPTINGIN  -> SCRIPTTYPE RAWHEX
 *
 * Driven by hand rather than by the test suite. Against a node with the fork active, fund each printed address, pass
 * the outpoint back, and give the raw transaction to testmempoolaccept. Every script type accepts, the signatures
 * carry 01 and 21, and a node that never scheduled the fork refuses the same transaction, which is the protection
 * being kept. The Shrike wallet repository carries the full procedure in docs/unified-sighash-regtest.md.
 */
public class SpareQuorumSpend {
    private static final String[] WORDS = {
            "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor",
            "sell arrive brand fluid cousin twin trap bar hen fine bicycle rack",
            "quantum lens tag pencil kingdom obey noise pigeon oyster shoulder ordinary tilt"};

    private static final ScriptType[] TYPES = {ScriptType.P2WSH, ScriptType.P2SH, ScriptType.P2SH_P2WSH};

    public static void main(String[] args) throws Exception {
        Network.set(Network.REGTEST);
        if(args.length == 0 || !(args[0].equals("addresses") || args[0].equals("spend"))) {
            throw new IllegalArgumentException("Usage: addresses | spend <scriptType> <txid> <vout> <value> <optingIn>");
        }

        if(args[0].equals("addresses")) {
            for(ScriptType scriptType : TYPES) {
                Wallet wallet = wallet(scriptType);
                System.out.println(scriptType.getName().replace(" ", "") + " " + wallet.getAddress(node(wallet)));
            }
            return;
        }

        ScriptType scriptType = typeOf(args[1]);
        Wallet wallet = wallet(scriptType);
        WalletNode node = node(wallet);
        Script spk = wallet.getOutputScript(node);
        long value = Long.parseLong(args[4]);
        int optingIn = Integer.parseInt(args[5]);

        Transaction transaction = new Transaction();
        transaction.setVersion(2);
        transaction.addInput(Sha256Hash.wrap(args[2]), Long.parseLong(args[3]), new Script(new byte[0]));
        transaction.addOutput(value - 2_000L, spk);

        PSBT psbt = new PSBT(transaction);
        PSBTInput psbtInput = psbt.getPsbtInputs().get(0);
        psbtInput.setWitnessUtxo(new TransactionOutput(null, value, spk.getProgram()));
        Script multisigScript = ScriptType.MULTISIG.getOutputScript(2, node.getPubKeys());
        if(scriptType == ScriptType.P2SH) {
            psbtInput.setRedeemScript(multisigScript);
        } else if(scriptType == ScriptType.P2SH_P2WSH) {
            psbtInput.setRedeemScript(ScriptType.P2WSH.getOutputScript(multisigScript));
            psbtInput.setWitnessScript(multisigScript);
        } else {
            psbtInput.setWitnessScript(multisigScript);
        }

        //The keystores whose keys sort last are the ones a key ordered choice drops, so those are the ones that opt in
        byte unifiedAll = (byte)(SigHash.UNIFIED_FLAG | SigHash.ALL.byteValue());
        List<ECKey> ordered = new ArrayList<>(node.getPubKeys());
        ordered.sort(new ECKey.LexicographicECKeyComparator());
        List<ECKey> optsIn = ordered.subList(ordered.size() - optingIn, ordered.size());
        for(Keystore keystore : wallet.getKeystores()) {
            psbtInput.setSigHash(optsIn.contains(keystore.getPubKey(node)) ? SigHash.fromByte(unifiedAll) : SigHash.ALL);
            if(!psbtInput.sign(keystore.getKey(node))) {
                throw new IllegalStateException("every keystore must sign");
            }
        }

        wallet.finalise(psbt);
        System.out.println(args[1] + " " + Utils.bytesToHex(psbt.extractTransaction().bitcoinSerialize()));
    }

    private static ScriptType typeOf(String name) {
        for(ScriptType scriptType : TYPES) {
            if(scriptType.getName().replace(" ", "").equals(name)) {
                return scriptType;
            }
        }
        throw new IllegalArgumentException("unknown script type " + name);
    }

    private static WalletNode node(Wallet wallet) {
        return wallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
    }

    private static Wallet wallet(ScriptType scriptType) throws Exception {
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
}
