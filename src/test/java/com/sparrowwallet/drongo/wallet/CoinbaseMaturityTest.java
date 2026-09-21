package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;

/**
 * How deep a coinbase output has to be before the wallet will spend it.
 *
 * A spend is checked as actual_maturity < required_maturity, where actual_maturity is the confirmations the output
 * has, and a transaction offering one any shallower is refused. The depth is a schedule rather than a settled number,
 * so the wallet has to read it off the network it is on rather than hold one figure.
 */
public class CoinbaseMaturityTest {
    @AfterEach
    public void tearDown() {
        Network.set(null);
    }

    @Test
    public void the_depth_is_the_one_the_network_asks_for() {
        //Taken from CoinbaseMaturityLongReleaseHeight minus CoinbaseMaturityLongStartHeight in the chain parameters
        Assertions.assertEquals(6480, Network.MAINNET.getCoinbaseMaturity(), "mainnet, 973440 to 979920");
        Assertions.assertEquals(6705, Network.TESTNET4.getCoinbaseMaturity(), "testnet4, 151406 to 158111");

        //Carrying no schedule, these keep the hundred the protocol has always asked for
        Assertions.assertEquals(100, Network.REGTEST.getCoinbaseMaturity(), "regtest carries no schedule");
        Assertions.assertEquals(100, Network.TESTNET.getCoinbaseMaturity(), "testnet carries no schedule");
        Assertions.assertEquals(100, Network.SIGNET.getCoinbaseMaturity(), "signet carries no schedule");
    }

    /**
     * The depth either side of the line, against the answer a node gave for the same two depths: a coinbase 6479 deep
     * is refused as a premature spend, and one 6480 deep is past the maturity check.
     */
    @Test
    public void a_coinbase_is_offered_only_once_it_is_deep_enough() {
        Network.set(Network.MAINNET);
        int maturity = Network.get().getCoinbaseMaturity();

        Assertions.assertFalse(eligible(maturity - 1), "a coinbase " + (maturity - 1) + " deep does not spend");
        Assertions.assertTrue(eligible(maturity), "a coinbase " + maturity + " deep does spend");
        Assertions.assertTrue(eligible(maturity + 1), "and anything deeper still does");
    }

    /** The hundred the wallet used to allow is far short of it, which is the whole of this. */
    @Test
    public void the_depth_the_wallet_used_to_allow_is_not_enough() {
        Network.set(Network.MAINNET);
        Assertions.assertFalse(eligible(Transaction.COINBASE_MATURITY_THRESHOLD),
                "a hundred confirmations was enough before the schedule and is not now");
    }

    /** Nothing here may touch an output that is not a coinbase, whatever its depth. */
    @Test
    public void an_ordinary_output_is_untouched() {
        Network.set(Network.MAINNET);
        Assertions.assertTrue(eligible(1, false), "an ordinary output spends at one confirmation");
    }

    private boolean eligible(int confirmations) {
        return eligible(confirmations, true);
    }

    private boolean eligible(int confirmations, boolean coinbase) {
        int tip = 1_000_000;
        //getConfirmations is tip - height + 1, the same count the network calls actual_maturity
        int height = tip - confirmations + 1;

        Transaction transaction = new Transaction();
        if(coinbase) {
            transaction.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new Script(new byte[0]));
        } else {
            transaction.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        }
        Assertions.assertEquals(coinbase, transaction.isCoinBase(), "the fixture must be what it claims to be");

        Wallet wallet = new Wallet();
        wallet.setStoredBlockHeight(tip);
        Sha256Hash txid = transaction.getTxId();
        wallet.updateTransactions(Map.of(txid, new BlockTransaction(txid, height, new Date(), 0L, transaction)));

        BlockTransactionHashIndex candidate = new BlockTransactionHashIndex(txid, height, new Date(), 0L, 0, 50_00000000L);
        Assertions.assertEquals(confirmations, candidate.getConfirmations(tip), "the fixture must sit at the depth it says");

        return new CoinbaseTxoFilter(wallet).isEligible(candidate);
    }

    /**
     * And through the path that actually chooses coins, so the filter is not merely correct in isolation.
     *
     * getSpendableUtxos is what a send is built from, and it is the only reason this matters: a depth that is only
     * counted in a balance is a wrong number on a screen, while one that reaches coin selection builds a transaction
     * the network will not take.
     */
    @Test
    public void an_immature_coinbase_is_not_offered_to_spend() throws Exception {
        Network.set(Network.MAINNET);
        int maturity = Network.get().getCoinbaseMaturity();

        Assertions.assertTrue(spendable(maturity - 1).isEmpty(), "a coinbase short of the depth may not be chosen");
        Assertions.assertFalse(spendable(maturity).isEmpty(), "and one that reaches it may");
    }

    /** A wallet holding one coinbase output that many confirmations deep, and what it will spend. */
    private Map<BlockTransactionHashIndex, WalletNode> spendable(int confirmations) throws Exception {
        int tip = 1_000_000;
        int height = tip - confirmations + 1;

        Wallet wallet = new Wallet();
        wallet.setPolicyType(com.sparrowwallet.drongo.policy.PolicyType.SINGLE_HD);
        wallet.setScriptType(com.sparrowwallet.drongo.protocol.ScriptType.P2WPKH);
        wallet.getKeystores().add(Keystore.fromSeed(new DeterministicSeed(
                "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0,
                DeterministicSeed.Type.BIP39), com.sparrowwallet.drongo.policy.PolicyType.SINGLE_HD,
                com.sparrowwallet.drongo.protocol.ScriptType.P2WPKH.getDefaultDerivation()));
        wallet.setDefaultPolicy(com.sparrowwallet.drongo.policy.Policy.getPolicy(
                com.sparrowwallet.drongo.policy.PolicyType.SINGLE_HD,
                com.sparrowwallet.drongo.protocol.ScriptType.P2WPKH, wallet.getKeystores(), null));
        wallet.setStoredBlockHeight(tip);
        WalletNode node = wallet.getNode(com.sparrowwallet.drongo.KeyPurpose.RECEIVE).getChildren().iterator().next();

        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new Script(new byte[0]));
        transaction.addOutput(50_00000000L, wallet.getOutputScript(node));
        Assertions.assertTrue(transaction.isCoinBase(), "the fixture must be a coinbase");

        Sha256Hash txid = transaction.getTxId();
        wallet.updateTransactions(Map.of(txid, new BlockTransaction(txid, height, new Date(), 0L, transaction)));
        node.getTransactionOutputs().add(new BlockTransactionHashIndex(txid, height, new Date(), 0L, 0, 50_00000000L));

        return wallet.getSpendableUtxos();
    }

    /**
     * A coinbase whose depth cannot be worked out is refused rather than offered.
     *
     * Every guard used to sit in one condition, so anything the filter could not answer fell through to spendable.
     * A wallet with no height cannot tell how deep its coinbase is, and offering it there builds a transaction the
     * network holds for as long as the rule stands.
     */
    @Test
    public void a_coinbase_whose_depth_is_unknown_is_not_offered() throws Exception {
        Network.set(Network.MAINNET);

        Wallet wallet = coinbaseWallet(1_000_000 - 10);
        wallet.setStoredBlockHeight(null);
        Assertions.assertTrue(wallet.getSpendableUtxos().isEmpty(), "with no height there is no depth to check against");

        wallet.setStoredBlockHeight(1_000_000);
        Assertions.assertTrue(wallet.getSpendableUtxos().isEmpty(), "and it is still short of the depth once there is");
    }

    /**
     * An account carries no height of its own until it is scanned, so the wallet it belongs to is asked before
     * giving up. Refusing on that alone would leave every mined coin in an account unspendable.
     */
    @Test
    public void an_account_falls_back_to_the_wallet_it_belongs_to() throws Exception {
        Network.set(Network.MAINNET);

        Wallet master = coinbaseWallet(1);
        master.setStoredBlockHeight(1_000_000);

        Wallet account = coinbaseWallet(1);
        account.setStoredBlockHeight(null);
        account.setMasterWallet(master);

        Assertions.assertFalse(account.isMasterWallet(), "the fixture must be an account");
        Assertions.assertFalse(account.getSpendableUtxos().isEmpty(),
                "a deep coinbase in an account is spendable, since the wallet it belongs to knows the height");
    }

    /** A txo whose transaction has not been fetched is still offered, or one of them would strand the wallet. */
    @Test
    public void a_txo_with_no_transaction_is_left_alone() throws Exception {
        Network.set(Network.MAINNET);

        Wallet wallet = coinbaseWallet(1);
        wallet.setStoredBlockHeight(1_000_000);

        //A hash this wallet holds no transaction for, which is what an unfetched one looks like here
        BlockTransactionHashIndex unfetched = new BlockTransactionHashIndex(
                Sha256Hash.wrap("11".repeat(32)), 1, new Date(), 0L, 0, 50_00000000L);
        Assertions.assertNull(wallet.getWalletTransaction(unfetched.getHash()), "the fixture must be unfetched");
        Assertions.assertTrue(new CoinbaseTxoFilter(wallet).isEligible(unfetched),
                "a txo whose transaction is absent may not be refused");
    }

    /** A wallet holding one coinbase output mined at the given height. */
    private Wallet coinbaseWallet(int height) throws Exception {
        Wallet wallet = new Wallet();
        wallet.setPolicyType(com.sparrowwallet.drongo.policy.PolicyType.SINGLE_HD);
        wallet.setScriptType(com.sparrowwallet.drongo.protocol.ScriptType.P2WPKH);
        wallet.getKeystores().add(Keystore.fromSeed(new DeterministicSeed(
                "absent essay fox snake vast pumpkin height crouch silent bulb excuse razor", "", 0,
                DeterministicSeed.Type.BIP39), com.sparrowwallet.drongo.policy.PolicyType.SINGLE_HD,
                com.sparrowwallet.drongo.protocol.ScriptType.P2WPKH.getDefaultDerivation()));
        wallet.setDefaultPolicy(com.sparrowwallet.drongo.policy.Policy.getPolicy(
                com.sparrowwallet.drongo.policy.PolicyType.SINGLE_HD,
                com.sparrowwallet.drongo.protocol.ScriptType.P2WPKH, wallet.getKeystores(), null));
        WalletNode node = wallet.getNode(com.sparrowwallet.drongo.KeyPurpose.RECEIVE).getChildren().iterator().next();

        Transaction transaction = new Transaction();
        transaction.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new Script(new byte[0]));
        transaction.addOutput(50_00000000L, wallet.getOutputScript(node));

        Sha256Hash txid = transaction.getTxId();
        wallet.updateTransactions(Map.of(txid, new BlockTransaction(txid, height, new Date(), 0L, transaction)));
        node.getTransactionOutputs().add(new BlockTransactionHashIndex(txid, height, new Date(), 0L, 0, 50_00000000L));
        return wallet;
    }

    /**
     * What is reported as immature is what the filter refuses, so the figure on the screen and the coins offered
     * cannot say different things.
     */
    @Test
    public void the_immature_balance_is_what_cannot_be_spent() throws Exception {
        Network.set(Network.MAINNET);
        int maturity = Network.get().getCoinbaseMaturity();
        int tip = 1_000_000;

        Wallet shallow = coinbaseWallet(tip - maturity + 2);
        shallow.setStoredBlockHeight(tip);
        Assertions.assertTrue(shallow.getSpendableUtxos().isEmpty(), "the fixture must be too shallow to spend");
        Assertions.assertEquals(50_00000000L, shallow.getImmatureBalance(), "all of it is immature");

        Wallet deep = coinbaseWallet(tip - maturity + 1);
        deep.setStoredBlockHeight(tip);
        Assertions.assertFalse(deep.getSpendableUtxos().isEmpty(), "the fixture must be deep enough to spend");
        Assertions.assertEquals(0L, deep.getImmatureBalance(), "nothing is immature once it can be spent");
    }
}
