package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CoinbaseTxoFilter implements TxoFilter {
    private static final Logger log = LoggerFactory.getLogger(CoinbaseTxoFilter.class);

    private static boolean loggedUnknownTransaction;

    private final Wallet wallet;

    public CoinbaseTxoFilter(Wallet wallet) {
        this.wallet = wallet;
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        BlockTransaction blockTransaction = wallet.getWalletTransaction(candidate.getHash());
        //Nothing says this is a coinbase, and refusing every txo whose transaction has not been fetched would
        //make an ordinary wallet unspendable over one of them. Nothing reaches here today, because a wallet cannot
        //hold a txo whose transaction it failed to fetch: ElectrumServer throws rather than admitting one. That is
        //an invariant this filter leans on and does not enforce, so say so once if it ever stops holding.
        if(blockTransaction == null || blockTransaction.getTransaction() == null) {
            if(!loggedUnknownTransaction) {
                loggedUnknownTransaction = true;
                log.warn("Cannot tell whether txo " + candidate.getHash() + ":" + candidate.getIndex()
                        + " is a coinbase, as its transaction is not present in the wallet. Allowing it to be spent. "
                        + "If it is an immature coinbase the network will reject the spend.");
            }

            return true;
        }

        if(!blockTransaction.getTransaction().isCoinBase()) {
            return true;
        }

        //A coinbase whose depth cannot be worked out is refused rather than offered. An account carries no height
        //of its own until it is scanned, so the wallet it belongs to is asked before giving up on one.
        Integer tip = wallet.getStoredBlockHeight();
        if(tip == null && !wallet.isMasterWallet()) {
            tip = wallet.getMasterWallet().getStoredBlockHeight();
        }
        if(tip == null) {
            return false;
        }

        return candidate.getConfirmations(tip) >= Network.get().getCoinbaseMaturity();
    }
}
