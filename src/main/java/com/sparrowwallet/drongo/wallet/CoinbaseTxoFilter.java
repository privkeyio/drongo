package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.Network;

public class CoinbaseTxoFilter implements TxoFilter {
    private final Wallet wallet;

    public CoinbaseTxoFilter(Wallet wallet) {
        this.wallet = wallet;
    }

    @Override
    public boolean isEligible(BlockTransactionHashIndex candidate) {
        BlockTransaction blockTransaction = wallet.getWalletTransaction(candidate.getHash());
        //Nothing says this is a coinbase, and refusing every txo whose transaction has not been fetched would
        //make an ordinary wallet unspendable over one of them
        if(blockTransaction == null || blockTransaction.getTransaction() == null) {
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
