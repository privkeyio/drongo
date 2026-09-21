package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionOutput;

/**
 * Asks a node how deep a coinbase output has to be, rather than trusting the number this wallet carries.
 *
 * The depth is a schedule and is expected to be raised again, at which point getCoinbaseMaturity() is quietly too
 * permissive and the wallet offers coins that will not relay. This builds the two transactions that find the line:
 * one spending a coinbase a confirmation short of the depth, which has to be refused, and one spending a coinbase at
 * exactly the depth, which has to get past the maturity check. Maturity is checked before scripts, so the signature
 * is irrelevant and the second one is expected to fail on the script instead.
 *
 *   CoinbaseMaturityProbe <network> <txid> [txid...]
 *
 * For each coinbase txid it prints a raw transaction to hand to testmempoolaccept. Pick the txids by taking the
 * coinbase of the block at tip minus depth plus one, for the depth either side of the number printed below. A refusal
 * reads `bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth N`, and N is the answer: if it
 * disagrees with the depth printed here, the schedule moved and Network.getCoinbaseMaturity() is stale.
 */
public class CoinbaseMaturityProbe {
    public static void main(String[] args) {
        if(args.length < 2) {
            throw new IllegalArgumentException("Usage: CoinbaseMaturityProbe <network> <txid> [txid...]");
        }

        Network network = Network.valueOf(args[0].toUpperCase());
        Network.set(network);
        System.out.println("network=" + network + " expects a coinbase to be " + network.getCoinbaseMaturity()
                + " confirmations deep");

        for(int i = 1; i < args.length; i++) {
            Transaction transaction = new Transaction();
            transaction.setVersion(2);
            transaction.addInput(Sha256Hash.wrap(args[i]), 0, new Script(new byte[0]));
            //Anywhere at all, since nothing here is meant to be broadcast
            transaction.addOutput(new TransactionOutput(transaction, 100_000L,
                    ScriptType.P2WPKH.getOutputScript(new byte[20])));
            System.out.println("probe " + args[i] + " " + Utils.bytesToHex(transaction.bitcoinSerialize()));
        }
    }
}
