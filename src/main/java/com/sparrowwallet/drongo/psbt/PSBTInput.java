package com.sparrowwallet.drongo.psbt;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentsDLEQProof;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static com.sparrowwallet.drongo.protocol.ScriptType.*;
import static com.sparrowwallet.drongo.protocol.TransactionSignature.Type.*;
import static com.sparrowwallet.drongo.psbt.PSBTEntry.*;

public class PSBTInput {
    public static final byte PSBT_IN_NON_WITNESS_UTXO = 0x00;
    public static final byte PSBT_IN_WITNESS_UTXO = 0x01;
    public static final byte PSBT_IN_PARTIAL_SIG = 0x02;
    public static final byte PSBT_IN_SIGHASH_TYPE = 0x03;
    public static final byte PSBT_IN_REDEEM_SCRIPT = 0x04;
    public static final byte PSBT_IN_WITNESS_SCRIPT = 0x05;
    public static final byte PSBT_IN_BIP32_DERIVATION = 0x06;
    public static final byte PSBT_IN_FINAL_SCRIPTSIG = 0x07;
    public static final byte PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
    public static final byte PSBT_IN_POR_COMMITMENT = 0x09;
    public static final byte PSBT_IN_RIPEMD160 = 0x0a;
    public static final byte PSBT_IN_SHA256 = 0x0b;
    public static final byte PSBT_IN_HASH160 = 0x0c;
    public static final byte PSBT_IN_HASH256 = 0x0d;
    public static final byte PSBT_IN_PREVIOUS_TXID = 0x0e;
    public static final byte PSBT_IN_OUTPUT_INDEX = 0x0f;
    public static final byte PSBT_IN_SEQUENCE = 0x10;
    public static final byte PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11;
    public static final byte PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12;
    public static final byte PSBT_IN_TAP_KEY_SIG = 0x13;
    public static final byte PSBT_IN_TAP_SCRIPT_SIG = 0x14;
    public static final byte PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
    public static final byte PSBT_IN_TAP_INTERNAL_KEY = 0x17;
    public static final byte PSBT_IN_SP_ECDH_SHARE = 0x1d;
    public static final byte PSBT_IN_SP_DLEQ = 0x1e;
    public static final byte PSBT_IN_SP_SPEND_BIP32_DERIVATION = 0x1f;
    public static final byte PSBT_IN_SP_TWEAK = 0x20;
    public static final byte PSBT_IN_PROPRIETARY = (byte)0xfc;

    private final PSBT psbt;
    private Transaction nonWitnessUtxo;
    private TransactionOutput witnessUtxo;
    private final Map<ECKey, TransactionSignature> partialSignatures = new LinkedHashMap<>();
    private SigHash sigHash;
    private Script redeemScript;
    private Script witnessScript;
    private final Map<ECKey, KeyDerivation> derivedPublicKeys = new LinkedHashMap<>();
    private Script finalScriptSig;
    private TransactionWitness finalScriptWitness;
    private String porCommitment;
    private byte[] ripeMd160Preimage;
    private byte[] sha256Preimage;
    private byte[] hash160Preimage;
    private byte[] hash256Preimage;
    private final Map<String, String> proprietary = new LinkedHashMap<>();
    /**
     * Taproot script path signatures, keyed by the x only public key and leaf hash they were made for.
     *
     * Kept rather than dropped so that a reader can tell they are there. The leaf script that would check them is
     * carried in PSBT_IN_TAP_LEAF_SCRIPT, which this does not parse, so these cannot be verified here: what they give
     * a caller is the fact that this input has been signed, which was otherwise unreadable and left an input carrying
     * only these looking exactly like an unsigned one.
     */
    private final Map<String, TransactionSignature> tapScriptSignatures = new LinkedHashMap<>();
    private TransactionSignature tapKeyPathSignature;
    private Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys = new LinkedHashMap<>();
    private ECKey tapInternalKey;

    //PSBTv2-only fields
    private Sha256Hash prevTxid;
    private Long prevIndex;
    private Long sequence;
    private Long requiredTimeLocktime;
    private Long requiredHeightLocktime;
    private final Map<ECKey, ECKey> silentPaymentsEcdhShares = new LinkedHashMap<>();
    private final Map<ECKey, SilentPaymentsDLEQProof> silentPaymentsDLEQProofs = new LinkedHashMap<>();
    private final Map<ECKey, KeyDerivation> silentPaymentsSpendDerivations = new LinkedHashMap<>();
    private byte[] silentPaymentsTweak;

    private int index;

    private static final Logger log = LoggerFactory.getLogger(PSBTInput.class);

    PSBTInput(PSBT psbt, int index) {
        this.psbt = psbt;
        this.index = index;
    }

    PSBTInput(PSBT psbt, ScriptType scriptType, int index, Transaction utxo, int utxoIndex, Long sequence, Script redeemScript, Script witnessScript,
              Map<ECKey, KeyDerivation> derivedPublicKeys, Map<String, String> proprietary, ECKey tapInternalKey, boolean alwaysAddNonWitnessTx, byte[] silentPaymentsTweak, Map<ECKey, KeyDerivation> silentPaymentsSpendDerivations) {
        this(psbt, index);

        if(Arrays.asList(ScriptType.WITNESS_TYPES).contains(scriptType)) {
            this.witnessUtxo = utxo.getOutputs().get(utxoIndex);
        } else {
            this.nonWitnessUtxo = utxo;
        }

        if(alwaysAddNonWitnessTx) {
            //Add non-witness UTXO to segwit v0 types to handle Trezor, Bitbox and Ledger requirements
            this.nonWitnessUtxo = utxo;
        }

        this.redeemScript = redeemScript;
        this.witnessScript = witnessScript;

        if(scriptType != P2TR) {
            this.derivedPublicKeys.putAll(derivedPublicKeys);
        }

        this.proprietary.putAll(proprietary);

        this.tapInternalKey = tapInternalKey == null ? null : ECKey.fromPublicOnly(tapInternalKey.getPubKeyXCoord());

        if(tapInternalKey != null && !derivedPublicKeys.values().isEmpty()) {
            KeyDerivation tapKeyDerivation = derivedPublicKeys.values().iterator().next();
            tapDerivedPublicKeys.put(this.tapInternalKey, Map.of(tapKeyDerivation, Collections.emptyList()));
        }

        this.sigHash = (scriptType == P2TR ? SigHash.DEFAULT : SigHash.ALL);

        //Populate PSBTv2 fields if parent PSBT is v2
        if(psbt.getPsbtVersion() >= 2) {
            this.prevTxid = utxo.getTxId();
            this.prevIndex = (long)utxoIndex;
            this.sequence = sequence;
        }

        this.silentPaymentsTweak = silentPaymentsTweak;
        this.silentPaymentsSpendDerivations.putAll(silentPaymentsSpendDerivations);
    }

    PSBTInput(PSBT psbt, List<PSBTEntry> inputEntries, int index) throws PSBTParseException {
        this(psbt, index);
        List<PSBTEntry> sortedEntries = new ArrayList<>(inputEntries);
        sortedEntries.sort((o1, o2) -> {
            int found1 = o1.getKeyType() == PSBT_IN_PREVIOUS_TXID || o1.getKeyType() == PSBT_IN_OUTPUT_INDEX ? 1 : 0;
            int found2 = o2.getKeyType() == PSBT_IN_PREVIOUS_TXID || o2.getKeyType() == PSBT_IN_OUTPUT_INDEX ? 1 : 0;
            return found2 - found1;
        });

        for(PSBTEntry entry : sortedEntries) {
            switch((byte)entry.getKeyType()) {
                case PSBT_IN_NON_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    Transaction nonWitnessTx = new Transaction(entry.getData());
                    nonWitnessTx.verify();
                    Sha256Hash inputHash = nonWitnessTx.calculateTxId(false);
                    Sha256Hash outpointHash = getPrevTxid();
                    if(outpointHash == null) {
                        throw new PSBTParseException("Outpoint hash not present for input " + index);
                    }
                    if(!outpointHash.equals(inputHash)) {
                        throw new PSBTParseException("Hash of provided non witness utxo transaction " + inputHash + " does not match transaction input outpoint hash " + outpointHash + " at index " + index);
                    }
                    this.nonWitnessUtxo = nonWitnessTx;
                    log.debug("Found input non witness utxo with txid: " + nonWitnessTx.getTxId() + " version " + nonWitnessTx.getVersion() + " size " + nonWitnessTx.getMessageSize() + " locktime " + nonWitnessTx.getLocktime());
                    for(TransactionInput input : nonWitnessTx.getInputs()) {
                        log.debug(" Transaction input references txid: " + input.getOutpoint().getHash() + " vout " + input.getOutpoint().getIndex() + " with script " + input.getScriptSig());
                    }
                    for(TransactionOutput output : nonWitnessTx.getOutputs()) {
                        log.debug(" Transaction output value: " + output.getValue() + (output.getScript().getToAddress() != null ? " to address " + output.getScript().getToAddress() : "") + " with script hex " + Utils.bytesToHex(output.getScript().getProgram()) + " to script " + output.getScript());
                    }
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    entry.checkOneByteKey();
                    TransactionOutput witnessTxOutput = new TransactionOutput(null, entry.getData(), 0);
                    if(witnessTxOutput.getValue() < 0 || witnessTxOutput.getValue() > Transaction.MAX_SATOSHIS) {
                        throw new PSBTParseException("Witness UTXO amount is out of range: " + witnessTxOutput.getValue());
                    }
                    if(!P2SH.isScriptType(witnessTxOutput.getScript()) && !P2WPKH.isScriptType(witnessTxOutput.getScript()) && !P2WSH.isScriptType(witnessTxOutput.getScript()) && !P2TR.isScriptType(witnessTxOutput.getScript())) {
                        throw new PSBTParseException("Witness UTXO provided for non-witness or unknown input");
                    }
                    this.witnessUtxo = witnessTxOutput;
                    try {
                        log.debug("Found input witness utxo amount " + witnessTxOutput.getValue() + " script hex " + Utils.bytesToHex(witnessTxOutput.getScript().getProgram()) + " script " + witnessTxOutput.getScript() + " addresses " + Arrays.asList(witnessTxOutput.getScript().getToAddresses()));
                    } catch(NonStandardScriptException e) {
                        log.error("Unknown script type", e);
                    }
                    break;
                case PSBT_IN_PARTIAL_SIG:
                    entry.checkOneBytePlusPubKey();
                    ECKey sigPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    if(entry.getData().length == 64 || entry.getData().length == 65) {
                        log.error("Schnorr signature provided as ECDSA partial signature, ignoring");
                        break;
                    }
                    //TODO: Verify signature
                    TransactionSignature signature = TransactionSignature.decodeFromBitcoin(ECDSA, entry.getData(), true);
                    this.partialSignatures.put(sigPublicKey, signature);
                    log.debug("Found input partial signature with public key " + sigPublicKey + " signature " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_SIGHASH_TYPE:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 4) {
                        throw new PSBTParseException("PSBT input sighash type must be 4 bytes");
                    }
                    long sighashType = Utils.readUint32(entry.getData(), 0);
                    SigHash sigHash;
                    try {
                        sigHash = SigHash.fromByte((byte)sighashType);
                    } catch(IllegalArgumentException e) {
                        //Consensus accepts any byte for bare, P2SH and segwit v0, so a PSBT can legitimately
                        //declare a type this enum does not model. Report it as a parse failure rather than
                        //letting an unchecked exception escape a constructor that declares PSBTParseException.
                        throw new PSBTParseException("Input " + index + " declares unsupported sighash type 0x" + Long.toHexString(sighashType));
                    }
                    this.sigHash = sigHash;
                    log.debug("Found input sighash_type " + sigHash.toString());
                    break;
                case PSBT_IN_REDEEM_SCRIPT:
                    entry.checkOneByteKey();
                    Script redeemScript = new Script(entry.getData());
                    this.redeemScript = redeemScript;
                    log.debug("Found input redeem script hex " + Utils.bytesToHex(redeemScript.getProgram()) + " script " + redeemScript);
                    break;
                case PSBT_IN_WITNESS_SCRIPT:
                    entry.checkOneByteKey();
                    Script witnessScript = new Script(entry.getData());
                    this.witnessScript = witnessScript;
                    log.debug("Found input witness script hex " + Utils.bytesToHex(witnessScript.getProgram()) + " script " + witnessScript);
                    break;
                case PSBT_IN_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    ECKey derivedPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    KeyDerivation keyDerivation = parseKeyDerivation(entry.getData());
                    this.derivedPublicKeys.put(derivedPublicKey, keyDerivation);
                    log.debug("Found input bip32_derivation with master fingerprint " + keyDerivation.getMasterFingerprint() + " at path " + keyDerivation.getDerivationPath() + " public key " + derivedPublicKey);
                    break;
                case PSBT_IN_FINAL_SCRIPTSIG:
                    entry.checkOneByteKey();
                    Script finalScriptSig = new Script(entry.getData());
                    this.finalScriptSig = finalScriptSig;
                    log.debug("Found input final scriptSig script hex " + Utils.bytesToHex(finalScriptSig.getProgram()) + " script " + finalScriptSig.toString());
                    break;
                case PSBT_IN_FINAL_SCRIPTWITNESS:
                    entry.checkOneByteKey();
                    TransactionWitness finalScriptWitness = new TransactionWitness(null, entry.getData(), 0);
                    this.finalScriptWitness = finalScriptWitness;
                    log.debug("Found input final scriptWitness " + finalScriptWitness.toString());
                    break;
                case PSBT_IN_POR_COMMITMENT:
                    entry.checkOneByteKey();
                    String porMessage = new String(entry.getData(), StandardCharsets.UTF_8);
                    this.porCommitment = porMessage;
                    log.debug("Found input POR commitment message " + porMessage);
                    break;
                case PSBT_IN_RIPEMD160:
                    entry.checkOneBytePlusRipe160Key();
                    if(!Arrays.equals(entry.getKeyData(), Ripemd160.getHash(entry.getData()))) {
                        throw new PSBTParseException("Hash of PSBT_IN_RIPEMD160 preimage did not match provided hash " + Utils.bytesToHex(entry.getKeyData()) + " " + Utils.bytesToHex(entry.getData()));
                    }
                    this.ripeMd160Preimage = entry.getData();
                    log.debug("Found input RIPEMD160 preimage " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_SHA256:
                    entry.checkOneBytePlusSha256Key();
                    if(!Arrays.equals(entry.getKeyData(), Sha256Hash.hash(entry.getData()))) {
                        throw new PSBTParseException("Hash of PSBT_IN_SHA256 preimage did not match provided hash " + Utils.bytesToHex(entry.getKeyData()) + " " + Utils.bytesToHex(entry.getData()));
                    }
                    this.sha256Preimage = entry.getData();
                    log.debug("Found input SHA256 preimage " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_HASH160:
                    entry.checkOneBytePlusRipe160Key();
                    if(!Arrays.equals(entry.getKeyData(), Utils.sha256hash160(entry.getData()))) {
                        throw new PSBTParseException("Hash of PSBT_IN_HASH160 preimage did not match provided hash " + Utils.bytesToHex(entry.getKeyData()) + " " + Utils.bytesToHex(entry.getData()));
                    }
                    this.hash160Preimage = entry.getData();
                    log.debug("Found input HASH160 preimage " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_HASH256:
                    entry.checkOneBytePlusSha256Key();
                    if(!Arrays.equals(entry.getKeyData(), Sha256Hash.hashTwice(entry.getData()))) {
                        throw new PSBTParseException("Hash of PSBT_IN_HASH256 preimage did not match provided hash " + Utils.bytesToHex(entry.getKeyData()) + " " + Utils.bytesToHex(entry.getData()));
                    }
                    this.hash256Preimage = entry.getData();
                    log.debug("Found input HASH256 preimage " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_PREVIOUS_TXID:
                    entry.checkOneByteKey();
                    this.prevTxid = Sha256Hash.wrap(Utils.reverseBytes(entry.getData()));
                    log.debug("Found input previous txid " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_OUTPUT_INDEX:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 4) {
                        throw new PSBTParseException("PSBT input output index must be 4 bytes");
                    }
                    this.prevIndex = Utils.readUint32(entry.getData(), 0);
                    log.debug("Found input previous output index " + this.prevIndex);
                    break;
                case PSBT_IN_SEQUENCE:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 4) {
                        throw new PSBTParseException("PSBT input sequence must be 4 bytes");
                    }
                    this.sequence = Utils.readUint32(entry.getData(), 0);
                    log.debug("Found input sequence " + this.sequence);
                    break;
                case PSBT_IN_REQUIRED_TIME_LOCKTIME:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 4) {
                        throw new PSBTParseException("PSBT input required time locktime must be 4 bytes");
                    }
                    long requiredTimeLocktime = Utils.readUint32(entry.getData(), 0);
                    if(requiredTimeLocktime < 500000000) {
                        throw new PSBTParseException("Required time locktime is less than 500000000");
                    }
                    this.requiredTimeLocktime = requiredTimeLocktime;
                    log.debug("Found input required time locktime " + this.requiredTimeLocktime);
                    break;
                case PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 4) {
                        throw new PSBTParseException("PSBT input required height locktime must be 4 bytes");
                    }
                    long requiredHeightLocktime = Utils.readUint32(entry.getData(), 0);
                    if(requiredHeightLocktime >= 500000000) {
                        throw new PSBTParseException("Required time locktime is greater than or equal to 500000000");
                    }
                    this.requiredHeightLocktime = requiredHeightLocktime;
                    log.debug("Found input required height locktime " + this.requiredHeightLocktime);
                    break;
                case PSBT_IN_SP_ECDH_SHARE:
                    entry.checkOneBytePlusPubKey();
                    if(entry.getData().length != 33) {
                        throw new PSBTParseException("PSBT input silent payments ECDH share data must be 33 bytes");
                    }
                    ECKey inputScanKey = ECKey.fromPublicOnly(entry.getKeyData());
                    ECKey inputEcdhShare = ECKey.fromPublicOnly(entry.getData());
                    this.silentPaymentsEcdhShares.put(inputScanKey, inputEcdhShare);
                    log.debug("Found input silent payments ECDH share for scan key: " + Utils.bytesToHex(entry.getKeyData()));
                    break;
                case PSBT_IN_SP_DLEQ:
                    entry.checkOneBytePlusPubKey();
                    if(entry.getData().length != 64) {
                        throw new PSBTParseException("PSBT input silent payments DLEQ proof data must be 64 bytes");
                    }
                    ECKey inputProofScanKey = ECKey.fromPublicOnly(entry.getKeyData());
                    SilentPaymentsDLEQProof inputDleqProof = SilentPaymentsDLEQProof.fromBytes(entry.getData());
                    this.silentPaymentsDLEQProofs.put(inputProofScanKey, inputDleqProof);
                    log.debug("Found input silent payments DLEQ proof for scan key: " + Utils.bytesToHex(entry.getKeyData()));
                    break;
                case PSBT_IN_SP_SPEND_BIP32_DERIVATION:
                    entry.checkOneBytePlusPubKey();
                    ECKey spSpendPubKey = ECKey.fromPublicOnly(entry.getKeyData());
                    KeyDerivation spSpendKeyDerivation = PSBTEntry.parseKeyDerivation(entry.getData());
                    this.silentPaymentsSpendDerivations.put(spSpendPubKey, spSpendKeyDerivation);
                    log.debug("Found input silent payments BIP32 derivation for spend key: " + Utils.bytesToHex(entry.getKeyData()));
                    break;
                case PSBT_IN_SP_TWEAK:
                    entry.checkOneByteKey();
                    if(entry.getData().length != 32) {
                        throw new PSBTParseException("PSBT input silent payments tweak must be 32 bytes");
                    }
                    this.silentPaymentsTweak = entry.getData();
                    log.debug("Found input silent payments tweak");
                    break;
                case PSBT_IN_PROPRIETARY:
                    entry.checkOneBytePlusKeyData();
                    this.proprietary.put(Utils.bytesToHex(entry.getKeyData()), Utils.bytesToHex(entry.getData()));
                    log.debug("Found proprietary input " + Utils.bytesToHex(entry.getKeyData()) + ": " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_TAP_KEY_SIG:
                    entry.checkOneByteKey();
                    this.tapKeyPathSignature = TransactionSignature.decodeFromBitcoin(SCHNORR, entry.getData(), true);
                    log.debug("Found input taproot key path signature " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_TAP_SCRIPT_SIG:
                    //One byte, then the x only public key and the leaf hash it signs under
                    if(entry.getKey().length != 65) {
                        throw new PSBTParseException("PSBT key type must be one byte plus x only pub key plus leaf hash");
                    }
                    this.tapScriptSignatures.put(Utils.bytesToHex(entry.getKeyData()), TransactionSignature.decodeFromBitcoin(SCHNORR, entry.getData(), true));
                    log.debug("Found input taproot script path signature " + Utils.bytesToHex(entry.getData()));
                    break;
                case PSBT_IN_TAP_BIP32_DERIVATION:
                    entry.checkOneBytePlusXOnlyPubKey();
                    ECKey tapPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    Map<KeyDerivation, List<Sha256Hash>> tapKeyDerivations = parseTaprootKeyDerivation(entry.getData());
                    if(tapKeyDerivations.isEmpty()) {
                        log.warn("PSBT provided an invalid input taproot key derivation");
                    } else {
                        this.tapDerivedPublicKeys.put(tapPublicKey, tapKeyDerivations);
                        for(KeyDerivation tapKeyDerivation : tapKeyDerivations.keySet()) {
                            log.debug("Found input taproot key derivation for key " + Utils.bytesToHex(entry.getKeyData()) + " with master fingerprint " + tapKeyDerivation.getMasterFingerprint() + " at path " + tapKeyDerivation.getDerivationPath());
                        }
                    }
                    break;
                case PSBT_IN_TAP_INTERNAL_KEY:
                    entry.checkOneByteKey();
                    this.tapInternalKey = ECKey.fromPublicOnly(entry.getData());
                    log.debug("Found input taproot internal key " + Utils.bytesToHex(entry.getData()));
                    break;
                default:
                    log.warn("PSBT input not recognized key type: " + entry.getKeyType());
            }
        }

        verifyUtxo();
    }

    /**
     * Verifies the utxo of this input is internally consistent, and that any provided redeem and witness scripts match it.
     * Only the non witness utxo is verified against the outpoint txid, so a witness utxo can only be relied on where the
     * sighash commits to the input amount - that is, where the input is a witness type.
     *
     * @throws PSBTParseException if the utxo, redeem script or witness script provided for this input are inconsistent
     */
    void verifyUtxo() throws PSBTParseException {
        //Any provided outpoint index must be present in the non witness utxo transaction, which is verified against the outpoint txid
        TransactionOutput nonWitnessUtxoOutput = getNonWitnessUtxoOutput();
        if(nonWitnessUtxo != null && getPrevIndex() != null && nonWitnessUtxoOutput == null) {
            throw new PSBTParseException("Non witness utxo transaction has no output at index " + getPrevIndex() + " for input " + index);
        }

        if(witnessUtxo != null && nonWitnessUtxoOutput != null
                && (witnessUtxo.getValue() != nonWitnessUtxoOutput.getValue() || !Arrays.equals(witnessUtxo.getScript().getProgram(), nonWitnessUtxoOutput.getScript().getProgram()))) {
            throw new PSBTParseException("Witness utxo of " + witnessUtxo.getValue() + " sats does not match the non witness utxo output of " + nonWitnessUtxoOutput.getValue() + " sats for input " + index);
        }

        //Witness utxos should only be provided for P2SH-P2WPKH or P2SH-P2WSH, as the legacy sighash does not commit to the input amount
        //A witness utxo that matches the txid verified non witness utxo output is redundant but harmless
        if(witnessUtxo != null && nonWitnessUtxoOutput == null && P2SH.isScriptType(witnessUtxo.getScript())) {
            Script nestedScript = redeemScript != null ? redeemScript : (finalScriptSig != null ? finalScriptSig.getFirstNestedScript() : null);
            if(nestedScript == null || (!P2WPKH.isScriptType(nestedScript) && !P2WSH.isScriptType(nestedScript))) {
                throw new PSBTParseException("Witness utxo provided for input " + index + " but redeem script is not P2WPKH or P2WSH");
            }
        }

        Script scriptPubKey = nonWitnessUtxoOutput != null ? nonWitnessUtxoOutput.getScript() : (witnessUtxo != null ? witnessUtxo.getScript() : null);

        if(redeemScript != null) {
            if(scriptPubKey == null) {
                log.warn("PSBT provided a redeem script for a transaction output that was not provided");
            } else if(!P2SH.isScriptType(scriptPubKey)) {
                throw new PSBTParseException("PSBT provided a redeem script for a transaction output that does not need one");
            } else if(!Arrays.equals(Utils.sha256hash160(redeemScript.getProgram()), scriptPubKey.getPubKeyHash())) {
                throw new PSBTParseException("Redeem script hash does not match transaction output script pubkey hash " + Utils.bytesToHex(scriptPubKey.getPubKeyHash()));
            }
        }

        if(witnessScript != null) {
            byte[] pubKeyHash = null;
            if(redeemScript != null && P2WSH.isScriptType(redeemScript)) { //P2SH-P2WSH
                pubKeyHash = redeemScript.getPubKeyHash();
            } else if(scriptPubKey != null && P2WSH.isScriptType(scriptPubKey)) { //P2WSH
                pubKeyHash = scriptPubKey.getPubKeyHash();
            }
            if(pubKeyHash == null) {
                log.warn("Witness script provided without P2WSH witness utxo or P2SH redeem script");
            } else if(!Arrays.equals(Sha256Hash.hash(witnessScript.getProgram()), pubKeyHash)) {
                throw new PSBTParseException("Witness script hash does not match provided pay to script hash " + Utils.bytesToHex(pubKeyHash));
            }
        }
    }

    private TransactionOutput getNonWitnessUtxoOutput() {
        Long prevIndex = getPrevIndex();
        if(nonWitnessUtxo == null || prevIndex == null || prevIndex < 0 || prevIndex >= nonWitnessUtxo.getOutputs().size()) {
            return null;
        }

        return nonWitnessUtxo.getOutputs().get(prevIndex.intValue());
    }

    public List<PSBTEntry> getInputEntries(int psbtVersion) {
        List<PSBTEntry> entries = new ArrayList<>();

        if(nonWitnessUtxo != null) {
            //Serialize all nonWitnessUtxo fields without witness data (pre-Segwit serialization) to reduce PSBT size
            entries.add(populateEntry(PSBT_IN_NON_WITNESS_UTXO, null, nonWitnessUtxo.bitcoinSerialize(false)));
        }

        if(witnessUtxo != null) {
            entries.add(populateEntry(PSBT_IN_WITNESS_UTXO, null, witnessUtxo.bitcoinSerialize()));
        }

        for(Map.Entry<ECKey, TransactionSignature> entry : partialSignatures.entrySet()) {
            entries.add(populateEntry(PSBT_IN_PARTIAL_SIG, entry.getKey().getPubKey(), entry.getValue().encodeToBitcoin()));
        }

        if(sigHash != null) {
            byte[] sigHashBytes = new byte[4];
            Utils.uint32ToByteArrayLE(sigHash.intValue(), sigHashBytes, 0);
            entries.add(populateEntry(PSBT_IN_SIGHASH_TYPE, null, sigHashBytes));
        }

        if(redeemScript != null) {
            entries.add(populateEntry(PSBT_IN_REDEEM_SCRIPT, null, redeemScript.getProgram()));
        }

        if(witnessScript != null) {
            entries.add(populateEntry(PSBT_IN_WITNESS_SCRIPT, null, witnessScript.getProgram()));
        }

        for(Map.Entry<ECKey, KeyDerivation> entry : derivedPublicKeys.entrySet()) {
            entries.add(populateEntry(PSBT_IN_BIP32_DERIVATION, entry.getKey().getPubKey(), serializeKeyDerivation(entry.getValue())));
        }

        if(finalScriptSig != null) {
            entries.add(populateEntry(PSBT_IN_FINAL_SCRIPTSIG, null, finalScriptSig.getProgram()));
        }

        if(finalScriptWitness != null) {
            entries.add(populateEntry(PSBT_IN_FINAL_SCRIPTWITNESS, null, finalScriptWitness.toByteArray()));
        }

        if(porCommitment != null) {
            entries.add(populateEntry(PSBT_IN_POR_COMMITMENT, null, porCommitment.getBytes(StandardCharsets.UTF_8)));
        }

        if(psbtVersion >= 2) {
            if(prevTxid != null) {
                entries.add(populateEntry(PSBT_IN_PREVIOUS_TXID, null, Utils.reverseBytes(prevTxid.getBytes())));
            }
            if(prevIndex != null) {
                byte[] prevIndexBytes = new byte[4];
                Utils.uint32ToByteArrayLE(prevIndex, prevIndexBytes, 0);
                entries.add(populateEntry(PSBT_IN_OUTPUT_INDEX, null, prevIndexBytes));
            }
            if(sequence != null) {
                byte[] sequenceBytes = new byte[4];
                Utils.uint32ToByteArrayLE(sequence, sequenceBytes, 0);
                entries.add(populateEntry(PSBT_IN_SEQUENCE, null, sequenceBytes));
            }
            if(requiredTimeLocktime != null) {
                byte[] requiredTimeLocktimeBytes = new byte[4];
                Utils.uint32ToByteArrayLE(requiredTimeLocktime, requiredTimeLocktimeBytes, 0);
                entries.add(populateEntry(PSBT_IN_REQUIRED_TIME_LOCKTIME, null, requiredTimeLocktimeBytes));
            }
            if(requiredHeightLocktime != null) {
                byte[] requiredHeightLocktimeBytes = new byte[4];
                Utils.uint32ToByteArrayLE(requiredHeightLocktime, requiredHeightLocktimeBytes, 0);
                entries.add(populateEntry(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, null, requiredHeightLocktimeBytes));
            }
            for(Map.Entry<ECKey, ECKey> entry : silentPaymentsEcdhShares.entrySet()) {
                entries.add(populateEntry(PSBT_IN_SP_ECDH_SHARE, entry.getKey().getPubKey(), entry.getValue().getPubKey()));
            }
            for(Map.Entry<ECKey, SilentPaymentsDLEQProof> entry : silentPaymentsDLEQProofs.entrySet()) {
                entries.add(populateEntry(PSBT_IN_SP_DLEQ, entry.getKey().getPubKey(), entry.getValue().getBytes()));
            }
            for(Map.Entry<ECKey, KeyDerivation> entry : silentPaymentsSpendDerivations.entrySet()) {
                entries.add(populateEntry(PSBT_IN_SP_SPEND_BIP32_DERIVATION, entry.getKey().getPubKey(), serializeKeyDerivation(entry.getValue())));
            }
            if(silentPaymentsTweak != null) {
                entries.add(populateEntry(PSBT_IN_SP_TWEAK, null, silentPaymentsTweak));
            }
        }

        for(Map.Entry<String, String> entry : proprietary.entrySet()) {
            entries.add(populateEntry(PSBT_IN_PROPRIETARY, Utils.hexToBytes(entry.getKey()), Utils.hexToBytes(entry.getValue())));
        }

        if(tapKeyPathSignature != null) {
            entries.add(populateEntry(PSBT_IN_TAP_KEY_SIG, null, tapKeyPathSignature.encodeToBitcoin()));
        }

        for(Map.Entry<String, TransactionSignature> entry : tapScriptSignatures.entrySet()) {
            entries.add(populateEntry(PSBT_IN_TAP_SCRIPT_SIG, Utils.hexToBytes(entry.getKey()), entry.getValue().encodeToBitcoin()));
        }

        for(Map.Entry<ECKey, Map<KeyDerivation, List<Sha256Hash>>> entry : tapDerivedPublicKeys.entrySet()) {
            if(!entry.getValue().isEmpty()) {
                entries.add(populateEntry(PSBT_IN_TAP_BIP32_DERIVATION, entry.getKey().getPubKeyXCoord(), serializeTaprootKeyDerivation(Collections.emptyList(), entry.getValue().keySet().iterator().next())));
            }
        }

        if(tapInternalKey != null) {
            entries.add(populateEntry(PSBT_IN_TAP_INTERNAL_KEY, null, tapInternalKey.getPubKeyXCoord()));
        }

        return entries;
    }

    /**
     * The declaration to take from a combine: the incoming output type, with the opt-in this input already decided.
     *
     * Whether to opt in is this wallet's decision, taken from the chain it is following. What comes back from a
     * co-signer is somebody else's PSBT, and letting its byte move that decision hands an outside party control of
     * what this wallet signs.
     *
     * Both directions matter, for different reasons. Clearing the opt-in is the damaging one: an unmarked device is
     * handed a copy asking for the base type, so the PSBT it returns declares the base type while this one still asks
     * for the opt-in, and adopting that would leave every signer that has not signed yet being asked for the legacy
     * digest, finishing a transaction that was reported as replay protected with none of it. Adding the opt-in is the
     * quieter one: this wallet only declines when it has a reason to, and on a chain that has not reached the
     * activation height the result is a transaction the network will hold and never mine.
     *
     * Any incoming type counts, not only the exact base or unified form of this one. A signer that answers with a
     * different output type than it was handed, a taproot one returning DEFAULT where ALL was asked for being the
     * ordinary case, would otherwise walk straight past a match on the base type.
     *
     * The signatures already gathered are unaffected either way: each names the type it was made over.
     */
    private static SigHash withDecidedOptIn(SigHash current, SigHash incoming) {
        if(current == null) {
            //Nothing declared here, so there is no decision of this wallet's to preserve
            return incoming;
        }

        if(!current.isUnified()) {
            return incoming.withoutUnified();
        }

        //DEFAULT has no output type to carry the bit, so there is no unified form of it to move to
        SigHash unified = incoming.withUnified();
        return unified.isUnified() ? unified : current;
    }

    void combine(PSBTInput psbtInput) {
        if(psbtInput.nonWitnessUtxo != null) {
            nonWitnessUtxo = psbtInput.nonWitnessUtxo;
        }

        if(psbtInput.witnessUtxo != null) {
            witnessUtxo = psbtInput.witnessUtxo;
        }

        partialSignatures.putAll(psbtInput.partialSignatures);

        if(psbtInput.sigHash != null) {
            sigHash = withDecidedOptIn(sigHash, psbtInput.sigHash);
        }

        if(psbtInput.redeemScript != null) {
            redeemScript = psbtInput.redeemScript;
        }

        if(psbtInput.witnessScript != null) {
            witnessScript = psbtInput.witnessScript;
        }

        derivedPublicKeys.putAll(psbtInput.derivedPublicKeys);

        if(psbtInput.porCommitment != null) {
            porCommitment = psbtInput.porCommitment;
        }

        if(psbtInput.ripeMd160Preimage != null) {
            ripeMd160Preimage = psbtInput.ripeMd160Preimage;
        }

        if(psbtInput.sha256Preimage != null) {
            sha256Preimage = psbtInput.sha256Preimage;
        }

        if(psbtInput.hash160Preimage != null) {
            hash160Preimage = psbtInput.hash160Preimage;
        }

        if(psbtInput.hash256Preimage != null) {
            hash256Preimage = psbtInput.hash256Preimage;
        }

        if(psbtInput.prevTxid != null) {
            prevTxid = psbtInput.prevTxid;
        }

        if(psbtInput.prevIndex != null) {
            prevIndex = psbtInput.prevIndex;
        }

        if(psbtInput.sequence != null) {
            sequence = psbtInput.sequence;
        }

        if(psbtInput.requiredTimeLocktime != null) {
            requiredTimeLocktime = psbtInput.requiredTimeLocktime;
        }

        if(psbtInput.requiredHeightLocktime != null) {
            requiredHeightLocktime = psbtInput.requiredHeightLocktime;
        }

        silentPaymentsEcdhShares.putAll(psbtInput.silentPaymentsEcdhShares);
        silentPaymentsDLEQProofs.putAll(psbtInput.silentPaymentsDLEQProofs);

        silentPaymentsSpendDerivations.putAll(psbtInput.silentPaymentsSpendDerivations);

        if(psbtInput.silentPaymentsTweak != null) {
            silentPaymentsTweak = psbtInput.silentPaymentsTweak;
        }

        proprietary.putAll(psbtInput.proprietary);

        if(psbtInput.tapKeyPathSignature != null) {
            tapKeyPathSignature = psbtInput.tapKeyPathSignature;
        }

        tapScriptSignatures.putAll(psbtInput.tapScriptSignatures);

        tapDerivedPublicKeys.putAll(psbtInput.tapDerivedPublicKeys);

        if(psbtInput.tapInternalKey != null) {
            tapInternalKey = psbtInput.tapInternalKey;
        }
    }

    public Map<String, TransactionSignature> getTapScriptSignatures() {
        return Collections.unmodifiableMap(tapScriptSignatures);
    }

    public Transaction getNonWitnessUtxo() {
        return nonWitnessUtxo;
    }

    public void setNonWitnessUtxo(Transaction nonWitnessUtxo) {
        this.nonWitnessUtxo = nonWitnessUtxo;
    }

    public TransactionOutput getWitnessUtxo() {
        return witnessUtxo;
    }

    public void setWitnessUtxo(TransactionOutput witnessUtxo) {
        this.witnessUtxo = witnessUtxo;
    }

    public TransactionSignature getPartialSignature(ECKey publicKey) {
        return partialSignatures.get(publicKey);
    }

    public SigHash getSigHash() {
        return sigHash;
    }

    public void setSigHash(SigHash sigHash) {
        this.sigHash = sigHash;
    }

    public Script getRedeemScript() {
        return redeemScript;
    }

    public void setRedeemScript(Script redeemScript) {
        this.redeemScript = redeemScript;
    }

    public Script getWitnessScript() {
        return witnessScript;
    }

    public void setWitnessScript(Script witnessScript) {
        this.witnessScript = witnessScript;
    }

    public KeyDerivation getKeyDerivation(ECKey publicKey) {
        return derivedPublicKeys.get(publicKey);
    }

    public Script getFinalScriptSig() {
        return finalScriptSig;
    }

    public void setFinalScriptSig(Script finalScriptSig) {
        this.finalScriptSig = finalScriptSig;
    }

    public TransactionWitness getFinalScriptWitness() {
        return finalScriptWitness;
    }

    public void setFinalScriptWitness(TransactionWitness finalScriptWitness) {
        this.finalScriptWitness = finalScriptWitness;
    }

    public String getPorCommitment() {
        return porCommitment;
    }

    public void setPorCommitment(String porCommitment) {
        this.porCommitment = porCommitment;
    }

    public Map<ECKey, TransactionSignature> getPartialSignatures() {
        return partialSignatures;
    }

    public ECKey getKeyForSignature(TransactionSignature signature) {
        for(Map.Entry<ECKey, TransactionSignature> entry : partialSignatures.entrySet()) {
            if(entry.getValue().equals(signature)) {
                return entry.getKey();
            }
        }

        return null;
    }

    public Map<ECKey, KeyDerivation> getDerivedPublicKeys() {
        return derivedPublicKeys;
    }

    public Map<String, String> getProprietary() {
        return proprietary;
    }

    public TransactionSignature getTapKeyPathSignature() {
        return tapKeyPathSignature;
    }

    public void setTapKeyPathSignature(TransactionSignature tapKeyPathSignature) {
        this.tapKeyPathSignature = tapKeyPathSignature;
    }

    public Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> getTapDerivedPublicKeys() {
        return tapDerivedPublicKeys;
    }

    public void setTapDerivedPublicKeys(Map<ECKey, Map<KeyDerivation, List<Sha256Hash>>> tapDerivedPublicKeys) {
        this.tapDerivedPublicKeys = tapDerivedPublicKeys;
    }

    public ECKey getTapInternalKey() {
        return tapInternalKey;
    }

    public void setTapInternalKey(ECKey tapInternalKey) {
        this.tapInternalKey = tapInternalKey;
    }

    public boolean isTaproot() {
        return getUtxo() != null && getScriptType() == P2TR;
    }

    public byte[] getRipeMd160Preimage() {
        return ripeMd160Preimage;
    }

    public void setRipeMd160Preimage(byte[] ripeMd160Preimage) {
        this.ripeMd160Preimage = ripeMd160Preimage;
    }

    public byte[] getSha256Preimage() {
        return sha256Preimage;
    }

    public void setSha256Preimage(byte[] sha256Preimage) {
        this.sha256Preimage = sha256Preimage;
    }

    public byte[] getHash160Preimage() {
        return hash160Preimage;
    }

    public void setHash160Preimage(byte[] hash160Preimage) {
        this.hash160Preimage = hash160Preimage;
    }

    public byte[] getHash256Preimage() {
        return hash256Preimage;
    }

    public void setHash256Preimage(byte[] hash256Preimage) {
        this.hash256Preimage = hash256Preimage;
    }

    public Sha256Hash getPrevTxid() {
        if(psbt.getPsbtVersion() >= 2) {
            return prevTxid;
        }

        return getInput().getOutpoint().getHash();
    }

    Sha256Hash prevTxid() {
        return prevTxid;
    }

    public void setPrevTxid(Sha256Hash prevTxid) {
        this.prevTxid = prevTxid;
    }

    public Long getPrevIndex() {
        if(psbt.getPsbtVersion() >= 2) {
            return prevIndex;
        }

        return getInput().getOutpoint().getIndex();
    }

    Long prevIndex() {
        return prevIndex;
    }

    public void setPrevIndex(Long prevIndex) {
        this.prevIndex = prevIndex;
    }

    public Long getSequence() {
        if(psbt.getPsbtVersion() >= 2) {
            return sequence;
        }

        return getInput().getSequenceNumber();
    }

    Long sequence() {
        return sequence;
    }

    public void setSequence(Long sequence) {
        this.sequence = sequence;
    }

    public Long getRequiredTimeLocktime() {
        return requiredTimeLocktime;
    }

    public void setRequiredTimeLocktime(Long requiredTimeLocktime) {
        this.requiredTimeLocktime = requiredTimeLocktime;
    }

    public Long getRequiredHeightLocktime() {
        return requiredHeightLocktime;
    }

    public void setRequiredHeightLocktime(Long requiredHeightLocktime) {
        this.requiredHeightLocktime = requiredHeightLocktime;
    }

    public Map<ECKey, ECKey> getSilentPaymentsEcdhShares() {
        return silentPaymentsEcdhShares;
    }

    public Map<ECKey, SilentPaymentsDLEQProof> getSilentPaymentsDLEQProofs() {
        return silentPaymentsDLEQProofs;
    }

    public Map<ECKey, KeyDerivation> getSilentPaymentsSpendDerivations() {
        return silentPaymentsSpendDerivations;
    }

    public byte[] getSilentPaymentsTweak() {
        return silentPaymentsTweak;
    }

    public void setSilentPaymentsTweak(byte[] silentPaymentsTweak) {
        this.silentPaymentsTweak = silentPaymentsTweak;
    }

    public boolean isSigned() {
        if(getTapKeyPathSignature() != null) {
            return true;
        } else if(!getPartialSignatures().isEmpty()) {
            try {
                //All partial sigs are already verified
                int reqSigs = getSigningScript().getNumRequiredSignatures();
                int sigs = getPartialSignatures().size();
                return sigs >= reqSigs;
            } catch(NonStandardScriptException e) {
                return false;
            }
        } else {
            return isFinalized();
        }
    }

    public Collection<TransactionSignature> getSignatures() {
        if(getFinalScriptWitness() != null) {
            return getFinalScriptWitness().getSignatures();
        } else if(getFinalScriptSig() != null) {
            return getFinalScriptSig().getSignatures();
        } else if(getTapKeyPathSignature() != null) {
            return List.of(getTapKeyPathSignature());
        } else {
            return getPartialSignatures().values();
        }
    }

    /**
     * The most signature checks worth making for one input, comfortably past the twenty keys consensus will check in a
     * multisig and far short of what a hostile input can ask for.
     */
    private static final int MAX_SIGNATURE_CHECKS = 1024;

    /**
     * The signatures on this input that verify against one of the given keys, each with the hash type it was made over.
     *
     * Needed because reading a signature off a signed input is a guess. A push is taken for a signature when it decodes
     * as one, and any 64 or 65 byte push decodes as a Schnorr signature whose hash type is simply its last byte, so a
     * taproot control block, an uncompressed public key or a run of miner data in a coinbase all read as signatures
     * carrying whatever byte they happen to end with. Anything that draws a conclusion from a hash type has to know it
     * read a real one, and the only way to know that is to check the signature against the message it names.
     *
     * The keys are the caller's to supply, and that is the whole of the guarantee. Every key an input carries is written
     * by whoever wrote the input: a partial signature names its own key, a derivation names any key at all, and a final
     * witness is arbitrary pushes. Checking against those answers "did someone sign something", which a stranger can
     * arrange for any hash type they like. Checking against keys the caller already trusts, its own wallet's, answers
     * whether one of those keys signed, which is the question a claim about this transaction rests on.
     *
     * It answers with less than is present, never more, and it does not throw. An input with no spent output has no
     * message to build, a hash type that names no message cannot be checked, a script that cannot be read leaves
     * nothing to check against, a tapscript path names a key this cannot recover, and an input asking for more checks
     * than any script could need is refused outright. Every one of those answers with fewer signatures, so a caller
     * reporting a protection has to treat what is missing as absent.
     */
    public List<TransactionSignature> getVerifiedSignatures(Collection<ECKey> trustedKeys) {
        //The spent output is what the message is built over, and getSigningScript reads it, so its absence is answered
        //here rather than thrown from there
        if(trustedKeys == null || trustedKeys.isEmpty() || getUtxo() == null) {
            return Collections.emptyList();
        }

        Script signingScript;
        try {
            signingScript = getSigningScript();
        } catch(RuntimeException e) {
            //Reading the script an input would be checked against parses what the input carries, and a final scriptSig
            //with nothing script shaped in it leaves that reading with nothing to unwrap. A caller drawing a label from
            //this must get an answer rather than an exception
            return Collections.emptyList();
        }

        if(signingScript == null) {
            return Collections.emptyList();
        }

        Collection<TransactionSignature> signatures = getSignatures();
        //Checking every signature against every key is a product, and the signatures are whatever the input carries, so
        //a hostile one can make it large: 200 pushes against 200 keys measured at two seconds, on whatever thread asked.
        //A script that spends needs a handful of each, twenty being the most consensus will check, so a shape past this
        //is not one to spend time on. Answering nothing rather than partly is what the rest of this promises anyway.
        if((long)trustedKeys.size() * signatures.size() > MAX_SIGNATURE_CHECKS) {
            return Collections.emptyList();
        }

        List<TransactionSignature> verified = new ArrayList<>();
        Map<Byte, Sha256Hash> sigHashes = new HashMap<>();
        for(TransactionSignature signature : signatures) {
            //Remembered even when it is null, so a hash type that names no message is worked out once rather than for
            //every signature carrying it: building one streams every input and every spent output
            if(!sigHashes.containsKey(signature.sighashFlags)) {
                Sha256Hash computed = null;
                try {
                    computed = getHashForSignature(signingScript, signature.sighashFlags);
                } catch(RuntimeException e) {
                    //A message that cannot be built is one that cannot be checked, which is the answer this gives
                    //anyway. It must not leave by way of an exception: a PSBT where another input carries no spent
                    //output is enough to reach this, and the caller is drawing a label rather than signing.
                }
                sigHashes.put(signature.sighashFlags, computed);
            }

            Sha256Hash hash = sigHashes.get(signature.sighashFlags);
            if(hash == null) {
                continue;
            }

            for(ECKey trustedKey : trustedKeys) {
                try {
                    if(trustedKey.verify(hash, signature)) {
                        verified.add(signature);
                        break;
                    }
                } catch(IllegalArgumentException e) {
                    //A key of the wrong kind for this signature verifies nothing, and says nothing about the others.
                    //Anything else, a missing native library among them, belongs to the caller: a check that cannot run
                    //must not read as a check that failed
                }
            }
        }

        return verified;
    }

    private SigHash getDefaultSigHash() {
        if(isTaproot()) {
            return SigHash.DEFAULT;
        }

        return SigHash.ALL;
    }

    public boolean signSilentPayments(ECKey spendPrivateKey) {
        if(getSilentPaymentsTweak() == null || getWitnessUtxo() == null) {
            return false;
        }

        ECKey tweakKey = ECKey.fromPrivate(getSilentPaymentsTweak());
        ECKey tweakedKey = spendPrivateKey.addPrivate(tweakKey);

        if(tweakedKey.hasOddYCoord()) {
            tweakedKey = tweakedKey.negatePrivate();
        }

        ECKey outputKey = ScriptType.P2TR.getPublicKeyFromScript(getWitnessUtxo().getScript());
        if(!Arrays.equals(tweakedKey.getPubKeyXCoord(), outputKey.getPubKeyXCoord())) {
            throw new IllegalStateException("Tweaked spend key does not match output key");
        }

        return sign(tweakedKey);
    }

    public boolean sign(ECKey privKey) {
        return sign(new PSBTInputSigner() {
            @Override
            public TransactionSignature sign(Sha256Hash hash, SigHash sigHash, TransactionSignature.Type signatureType) {
                return privKey.sign(hash, sigHash, signatureType);
            }

            @Override
            public ECKey getPubKey() {
                return ECKey.fromPublicOnly(privKey);
            }
        });
    }

    public boolean sign(PSBTInputSigner psbtInputSigner) {
        SigHash localSigHash = getSigHash();
        if(localSigHash == null) {
            localSigHash = getDefaultSigHash();
        }

        if(getNonWitnessUtxo() != null || getWitnessUtxo() != null) {
            Script signingScript = getSigningScript();
            if(signingScript != null) {
                if((localSigHash == SigHash.SINGLE || localSigHash == SigHash.ANYONECANPAY_SINGLE) && index >= psbt.getTransaction().getOutputs().size()) {
                    throw new IllegalStateException("Refusing to sign SIGHASH_SINGLE on input " + index
                            + " with only " + psbt.getTransaction().getOutputs().size() + " output(s) as it would produce a re-broadcastable signature");
                }

                Sha256Hash hash = getHashForSignature(signingScript, localSigHash);
                if(hash == null) {
                    //getHashForSignature answers null where the message cannot be built, which for a PSBT missing the
                    //UTXO of some other input is the ordinary case rather than a hostile one. Signing over null would
                    //reach ECKey.sign as a NullPointerException and be reported as "Failed to Sign: null".
                    throw new IllegalStateException("Cannot sign input " + index + " with hash type "
                            + localSigHash + ": the message for it cannot be built from this PSBT");
                }

                TransactionSignature.Type type = isTaproot() ? SCHNORR : ECDSA;
                TransactionSignature transactionSignature = psbtInputSigner.sign(hash, localSigHash, type);

                if(type == SCHNORR) {
                    tapKeyPathSignature = transactionSignature;
                } else {
                    ECKey pubKey = psbtInputSigner.getPubKey();
                    getPartialSignatures().put(pubKey, transactionSignature);
                }

                return true;
            }
        }

        return false;
    }

    void verifySigHash() throws PSBTSignatureException {
        //The opt-in bit selects an algorithm, not what the signature covers, so an opted-in type is as
        //safe or unsafe as the type it is built on and has to reach the same warning. Stripping it here
        //means a new opt-in constant can never quietly bypass this gate.
        SigHash sigHash = (this.sigHash == null ? null : this.sigHash.withoutUnified());

        if(sigHash == null || sigHash == SigHash.ALL || sigHash == SigHash.DEFAULT) {
            return;
        }

        int numOutputs = psbt.getTransaction().getOutputs().size();
        if((sigHash == SigHash.SINGLE || sigHash == SigHash.ANYONECANPAY_SINGLE) && index >= numOutputs) {
            throw new PSBTSignatureException("Input " + index + " requests " + (sigHash == SigHash.ANYONECANPAY_SINGLE ? "SIGHASH_SINGLE | ANYONECANPAY" : "SIGHASH_SINGLE")
                    + ", but the transaction has only " + numOutputs + " output(s), so there is no output at that index. The signature would commit to no outputs at all, and could be re-used on a transaction with completely different outputs.");
        }

        switch(sigHash) {
            case NONE:
                throw new PSBTSignatureException("Input " + index + " requests SIGHASH_NONE. The signature does not commit to any of the outputs, and can be re-used on a transaction with completely different outputs.");
            case ANYONECANPAY_NONE:
                throw new PSBTSignatureException("Input " + index + " requests SIGHASH_NONE | ANYONECANPAY. The signature commits to neither inputs nor outputs and can be re-used in nearly any transaction.");
            case ANYONECANPAY_SINGLE:
                throw new PSBTSignatureException("Input " + index + " requests SIGHASH_SINGLE | ANYONECANPAY. The signature only commits to one output, and other inputs may be added after signing.");
            case SINGLE:
                throw new PSBTSignatureException("Input " + index + " requests SIGHASH_SINGLE. The signature only commits to the output at the same index, allowing other outputs to be added or modified after signing.");
            case ANYONECANPAY_ALL:
                throw new PSBTSignatureException("Input " + index + " requests SIGHASH_ALL | ANYONECANPAY. Other inputs may be added to the transaction after signing, potentially redirecting value through fees.");
            case ANYONECANPAY:
                throw new PSBTSignatureException("Input " + index + " requests a non-standard ANYONECANPAY sighash with no base type. The resulting signature has unpredictable commitment semantics.");
        }
    }

    /**
     * A signature whose hash type names no digest cannot be checked, and an unverifiable signature is reported as one
     * rather than passed over. Refusing here is what keeps a hash type the script type reserved from reading as
     * verified.
     */
    private void requireDigest(Sha256Hash hash, byte sigHashType) throws PSBTSignatureException {
        if(hash == null) {
            throw new PSBTSignatureException("Input " + index + " carries a signature with hash type "
                    + Integer.toHexString(Byte.toUnsignedInt(sigHashType)) + ", which names no digest for this input");
        }
    }

    /**
     * The hash types a signature on this input is allowed to carry.
     *
     * Checking each signature against the type it names, rather than against the one the input declares, is what lets
     * an opted-in signature sit beside a legacy one. Taken alone it would also accept a signature over any other type,
     * so a signer that returned SIGHASH_NONE where ALL was asked for would verify and finalise, and that signature
     * commits to no outputs at all. The opt-in bit is the only thing a signer is allowed to differ on, because that
     * is the only thing this wallet varies per signer: an unmarked one is handed the base type of what the input
     * declares. Anything else was not asked for by anyone.
     */
    private boolean isRequestedType(SigHash declared, byte sigHashType) {
        if(declared == null) {
            return true;
        }

        return sigHashType == declared.value
                || sigHashType == declared.withUnified().value
                || sigHashType == declared.withoutUnified().value;
    }

    private void requireRequestedType(SigHash declared, byte sigHashType) throws PSBTSignatureException {
        if(!isRequestedType(declared, sigHashType)) {
            throw new PSBTSignatureException("Input " + index + " carries a signature with hash type "
                    + Integer.toHexString(Byte.toUnsignedInt(sigHashType)) + ", which is not the "
                    + declared + " this input asks for");
        }
    }

    boolean verifySignatures() throws PSBTSignatureException {
        if(getNonWitnessUtxo() != null || getWitnessUtxo() != null) {
            Script signingScript = getSigningScript();
            if(signingScript != null) {
                //One marked signer is enough, so an input can carry an opted-in signature beside a legacy one while
                //declaring only one of those types. Each signature names the type it was made over, and that is what
                //it has to be checked against, the way getSigningKeys() resolves them at finalise time. Bounded to the
                //types this input actually asks for, or checking each signature against its own byte would accept one
                //made over a type nobody requested.
                SigHash declared = getSigHash() == null ? getDefaultSigHash() : getSigHash();
                Map<Byte, Sha256Hash> sigHashes = new HashMap<>();

                if(isTaproot() && tapKeyPathSignature != null) {
                    ECKey outputKey = P2TR.getPublicKeyFromScript(getUtxo().getScript());
                    requireRequestedType(declared, tapKeyPathSignature.sighashFlags);
                    Sha256Hash hash = sigHashes.computeIfAbsent(tapKeyPathSignature.sighashFlags, sigHashType -> getHashForSignature(signingScript, sigHashType));
                    requireDigest(hash, tapKeyPathSignature.sighashFlags);
                    if(!outputKey.verify(hash, tapKeyPathSignature)) {
                        throw new PSBTSignatureException("Tweaked internal key does not verify against provided taproot keypath signature");
                    }
                } else {
                    for(ECKey sigPublicKey : getPartialSignatures().keySet()) {
                        TransactionSignature signature = getPartialSignature(sigPublicKey);
                        requireRequestedType(declared, signature.sighashFlags);
                        Sha256Hash hash = sigHashes.computeIfAbsent(signature.sighashFlags, sigHashType -> getHashForSignature(signingScript, sigHashType));
                        requireDigest(hash, signature.sighashFlags);
                        if(!sigPublicKey.verify(hash, signature)) {
                            throw new PSBTSignatureException("Partial signature does not verify against provided public key");
                        }
                    }
                }

                //TODO: Implement Bitcoin Script engine to verify finalScriptSig and finalScriptWitness

                return true;
            }
        }

        return false;
    }

    public Map<ECKey, TransactionSignature> getSigningKeys(Set<ECKey> availableKeys) {
        Collection<TransactionSignature> signatures = getSignatures();
        Script signingScript = getSigningScript();

        Map<ECKey, TransactionSignature> signingKeys = new LinkedHashMap<>();
        if(signingScript != null) {
            Map<Byte, Sha256Hash> sigHashes = new HashMap<>();

            for(ECKey sigPublicKey : availableKeys) {
                for(TransactionSignature signature : signatures) {
                    Sha256Hash hash = sigHashes.computeIfAbsent(signature.sighashFlags, sigHashType -> getHashForSignature(signingScript, sigHashType));

                    //A hash type that names no digest cannot have been signed by any key here, so it attributes to
                    //none rather than throwing out of an attribution that has no way to report an error
                    if(hash != null && sigPublicKey.verify(hash, signature)) {
                        signingKeys.put(sigPublicKey, signature);
                    }
                }
            }
        }

        return signingKeys;
    }

    public ScriptType getScriptType() {
        TransactionOutput utxo = getUtxo();
        if(utxo == null) {
            return null;
        }

        Script signingScript = utxo.getScript();

        boolean p2sh = false;
        if(P2SH.isScriptType(signingScript)) {
            p2sh = true;

            if(getRedeemScript() != null) {
                signingScript = getRedeemScript();
            } else if(getFinalScriptSig() != null) {
                signingScript = getFinalScriptSig().getFirstNestedScript();
            } else {
                return null;
            }
        }

        if(P2WPKH.isScriptType(signingScript)) {
            return p2sh ? P2SH_P2WPKH : P2WPKH;
        } else if(P2WSH.isScriptType(signingScript)) {
            return p2sh ? P2SH_P2WSH : P2WSH;
        } else if(MULTISIG.isScriptType(signingScript)) {
            return p2sh ? P2SH : MULTISIG;
        }

        return ScriptType.getType(signingScript);
    }

    public Script getSigningScript() {
        Script signingScript = getUtxo().getScript();

        if(P2SH.isScriptType(signingScript)) {
            if(getRedeemScript() != null) {
                signingScript = getRedeemScript();
            } else if(getFinalScriptSig() != null) {
                signingScript = getFinalScriptSig().getFirstNestedScript();
            } else {
                return null;
            }
        }

        if(P2WPKH.isScriptType(signingScript)) {
            signingScript = ScriptType.P2PKH.getOutputScript(signingScript.getPubKeyHash());
        } else if(P2WSH.isScriptType(signingScript)) {
            if(getWitnessScript() != null) {
                signingScript = getWitnessScript();
            } else if(getFinalScriptWitness() != null && getFinalScriptWitness().getWitnessScript() != null) {
                return getFinalScriptWitness().getWitnessScript();
            } else {
                return null;
            }
        }

        if(P2TR.isScriptType(signingScript)) {
            //For now, only support keypath spends and just return the ScriptPubKey
            //In future return the script from PSBT_IN_TAP_LEAF_SCRIPT
        }

        return signingScript;
    }

    public boolean isFinalized() {
        return getFinalScriptSig() != null || getFinalScriptWitness() != null;
    }

    public TransactionInput getInput() {
        return psbt.getTransaction().getInputs().get(index);
    }

    public TransactionOutput getUtxo() {
        //Prefer the non witness utxo, as it is the only form verified against the outpoint txid
        TransactionOutput nonWitnessUtxoOutput = getNonWitnessUtxoOutput();
        return nonWitnessUtxoOutput != null ? nonWitnessUtxoOutput : getWitnessUtxo();
    }

    int getIndex() {
        return index;
    }

    void setIndex(int index) {
        this.index = index;
    }

    public void clearNonFinalFields() {
        partialSignatures.clear();
        sigHash = null;
        redeemScript = null;
        witnessScript = null;
        porCommitment = null;
        proprietary.clear();
        tapDerivedPublicKeys.clear();
        tapKeyPathSignature = null;
        tapScriptSignatures.clear();
        silentPaymentsEcdhShares.clear();
        silentPaymentsDLEQProofs.clear();
        silentPaymentsSpendDerivations.clear();
        silentPaymentsTweak = null;
    }

    private Sha256Hash getHashForSignature(Script connectedScript, SigHash localSigHash) {
        return getHashForSignature(connectedScript, localSigHash.value);
    }

    /**
     * The digest a signature carrying this hash type byte was made over, or null where the byte names none.
     *
     * The unified message refuses, for taproot and tapscript, the hash types BIP341 reserved, and the byte here comes
     * off the wire: a schnorr signature is 65 bytes with any trailing byte, so anyone who can hand this wallet a PSBT
     * can put a reserved one in it.
     * Returning null lets the callers say the signature does not verify, which is true, rather than letting an
     * unchecked exception out of a signature check and taking the screen with it.
     */
    private Sha256Hash getHashForSignature(Script connectedScript, byte sigHashType) {
        Sha256Hash hash;

        ScriptType scriptType = getScriptType();
        //Tested on the bit rather than through SigHash.fromByte, because this overload is handed hash type bytes
        //taken off the wire and one that is not a defined type must not throw out of a signature check.
        if((sigHashType & SigHash.UNIFIED_FLAG) != 0) {
            //The unified algorithm covers every script type, so it is selected by the opt-in bit rather than
            //by the input's kind. The kind only decides which script type byte and tail the message carries.
            try {
                hash = getHashForUnifiedSignature(connectedScript, sigHashType, scriptType);
            } catch(IllegalArgumentException e) {
                return null;
            }
        } else if(scriptType == ScriptType.P2TR) {
            List<TransactionOutput> spentUtxos = psbt.getPsbtInputs().stream().map(PSBTInput::getUtxo).collect(Collectors.toList());
            hash = psbt.getTransaction().hashForTaprootSignature(spentUtxos, index, !P2TR.isScriptType(connectedScript), connectedScript, sigHashType, null);
        } else if(Arrays.asList(WITNESS_TYPES).contains(scriptType)) {
            long prevValue = getUtxo().getValue();
            hash = psbt.getTransaction().hashForWitnessSignature(index, connectedScript.getProgram(), prevValue, sigHashType);
        } else {
            hash = psbt.getTransaction().hashForLegacySignature(index, connectedScript.getProgram(), sigHashType);
        }

        return hash;
    }

    private Sha256Hash getHashForUnifiedSignature(Script connectedScript, byte sigHashType, ScriptType scriptType) {
        //Every spent output is committed to, not just this input's, which is what closes CVE-2020-14199.
        //PSBT already carries them per input.
        List<TransactionOutput> spentUtxos = psbt.getPsbtInputs().stream().map(PSBTInput::getUtxo).collect(Collectors.toList());

        UnifiedScriptType unifiedScriptType;
        byte[] scriptCode = null;
        byte[] tapLeafHash = null;
        if(scriptType == ScriptType.P2TR) {
            if(P2TR.isScriptType(connectedScript)) {
                unifiedScriptType = UnifiedScriptType.TAPROOT;
            } else {
                unifiedScriptType = UnifiedScriptType.TAPSCRIPT;
                tapLeafHash = Transaction.getTapLeafHash(connectedScript);
            }
        } else if(Arrays.asList(WITNESS_TYPES).contains(scriptType)) {
            unifiedScriptType = UnifiedScriptType.WITNESS_V0;
            scriptCode = connectedScript.getProgram();
        } else {
            unifiedScriptType = UnifiedScriptType.BARE;
            scriptCode = connectedScript.getProgram();
        }

        return psbt.getTransaction().hashForUnifiedSignature(spentUtxos, index, unifiedScriptType, scriptCode, sigHashType, null, tapLeafHash, null);
    }

}
