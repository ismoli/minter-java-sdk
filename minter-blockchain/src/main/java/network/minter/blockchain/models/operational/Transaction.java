/*
 * Copyright (C) by MinterTeam. 2020
 * @link <a href="https://github.com/MinterTeam">Org Github</a>
 * @link <a href="https://github.com/edwardstock">Maintainer Github</a>
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package network.minter.blockchain.models.operational;





import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import network.minter.blockchain.BuildConfig;
import network.minter.core.MinterSDK;
import network.minter.core.crypto.BytesData;
import network.minter.core.crypto.MinterAddress;
import network.minter.core.crypto.PrivateKey;
import com.edwardstock.secp256k1.NativeSecp256k1;
import network.minter.core.util.DecodeResult;
import network.minter.core.util.RLPBoxed;

import static network.minter.blockchain.models.operational.Transaction.SignatureType.Multi;
import static network.minter.blockchain.models.operational.Transaction.SignatureType.Single;
import static network.minter.core.internal.common.Preconditions.checkArgument;
import static network.minter.core.internal.common.Preconditions.checkNotNull;
import static network.minter.core.internal.common.Preconditions.firstNonNull;
import static network.minter.core.internal.helpers.BytesHelper.charsToBytes;
import static network.minter.core.internal.helpers.BytesHelper.fixBigintSignedByte;
import static network.minter.core.internal.helpers.StringHelper.charsToString;
import static network.minter.core.internal.helpers.StringHelper.strrpad;

/**
 * minter-android-blockchain. 2018
 * @author Eduard Maximovich <edward.vstock@gmail.com>
 */
public class Transaction  {
    public final static BigInteger VALUE_MUL = new BigInteger("1000000000000000000", 10);
    public final static BigDecimal VALUE_MUL_DEC = new BigDecimal("1000000000000000000");


    public static BigDecimal humanizeValue(BigInteger in) {
        return new BigDecimal(in).divide(VALUE_MUL_DEC);
    }

    public static BigInteger normalizeValue(BigDecimal in) {
        return in.multiply(VALUE_MUL_DEC).toBigInteger();
    }

    public static BigInteger normalizeValue(CharSequence in) {
        if (in == null) return BigInteger.ZERO;
        return new BigDecimal(in.toString()).multiply(VALUE_MUL_DEC).toBigInteger();
    }

    BigInteger mNonce;
    BlockchainID mChainId;
    BigInteger mGasPrice = new BigInteger("1");
    long mGasCoin = MinterSDK.DEFAULT_COIN.id;
    OperationType mType = OperationType.SendCoin;
    Operation mOperationData;

    // max - 1024 bytes (1 kilobyte)
    BytesData mPayload = new BytesData(new char[0]);
    BytesData mServiceData = new BytesData(new char[0]);
    SignatureType mSignatureType = Single;
    SignatureData mSignatureData;

    public enum SignatureType {
        Single((byte) 0x01, SignatureSingleData.class),
        Multi((byte) 0x02, SignatureMultiData.class);

        BigInteger mVal;
        Class<? extends SignatureData> mTypeClass;

        SignatureType(byte val, Class<? extends SignatureData> cls) {
            mVal = new BigInteger(String.valueOf(val));
            mTypeClass = cls;
        }

        public static SignatureType findByValue(BigInteger val) {
            for (SignatureType t : SignatureType.values()) {
                if (t.getValue().equals(val)) {
                    return t;
                }
            }

            return null;
        }

        public BigInteger getValue() {
            return mVal;
        }

        public Class<? extends SignatureData> getSignClass() {
            return mTypeClass;
        }
    }

    protected Transaction(BigInteger nonce) {
        mNonce = nonce;
    }

    protected Transaction() {
    }


    /**
     * Decodes raw hex-encoded transaction
     * @param hexEncoded transaction in hex string
     * @return Valid transaction with operation data
     */
    public static Transaction fromEncoded(@Nonnull String hexEncoded) {
        checkNotNull(hexEncoded, "hexEncoded data can't be null");
        checkArgument(hexEncoded.length() > 0, "Encoded transaction is empty");
        final BytesData bd = new BytesData(hexEncoded);
        final DecodeResult rlp = RLPBoxed.decode(bd.getData(), 0);
        final Object[] decoded = (Object[]) rlp.getDecoded();

        if (decoded.length < 10) {
            throw new InvalidEncodedTransactionException("Encoded transaction has invalid data length: expected 10, given %d", decoded.length);
        }

        Transaction transaction = new Transaction();
        transaction.decodeRLP(decoded);

        try {
            transaction.mOperationData = transaction.mType.getOpClass().getDeclaredConstructor(Transaction.class).newInstance(transaction);
            transaction.mOperationData.decodeRLP(transaction.fromRawRlp(5, decoded));
        } catch (Throwable e) {
            throw new InvalidEncodedTransactionException("Unable to decode transaction data field", e);
        }

        try {
            transaction.mSignatureData = transaction.mSignatureType.getSignClass().newInstance();
            transaction.mSignatureData.decodeRLP(transaction.fromRawRlp(9, decoded));
        } catch (Throwable e) {
            throw new InvalidEncodedTransactionException("Unable to decode transaction signature data field", e);
        }

        return transaction;
    }

    /**
     * Use this to decrease object lifetime (especially if you need to create final instance of this object)
     */
    public void cleanup() {
        mNonce = null;
        mChainId = null;
        mGasPrice = null;
        mGasCoin = 0;
        mType = null;
        mOperationData = null;
        mPayload = null;
        mServiceData = null;
        mSignatureType = null;
        mSignatureData = null;
    }

    /**
     * Signature type
     * @return {@link SignatureType}
     * @see SignatureType
     * @see SignatureData
     */
    public SignatureType getSignatureType() {
        return mSignatureType;
    }

    /**
     * Signature data (for single or multi)
     * @param cls class to cast with
     * @param <SignData> type extends signature data
     * @return object extends {@link SignatureData}
     */
    public <SignData extends SignatureData> SignData getSignatureData(Class<SignData> cls) {
        return cls.cast(mSignatureData);
    }

    /**
     * Signature data (for single or multi)
     * @param <SignData> type of signature data
     * @return object extends {@link SignatureData}
     */
    @SuppressWarnings("unchecked")
    public <SignData extends SignatureData> SignData getSignatureData() {
        return (SignData) mSignatureData;
    }

    public BigInteger getNonce() {
        return mNonce;
    }

    public BigInteger getGasPrice() {
        return mGasPrice;
    }

    public OperationType getType() {
        return mType;
    }

    /**
     * Sign multi signature transaction data with private keys
     * @param privateKeys private key list to sign with
     * @return {@link TransactionSign} Raw transaction sign
     * @since 0.3.0
     */
    public TransactionSign signMulti(MinterAddress signatureAddress, @Nonnull final List<PrivateKey> privateKeys) {
        mSignatureType = Multi;
        checkArgument(privateKeys.size() > 0, "Private keys can't be empty");

        final BytesData rawTxData = new BytesData(encode(true));
        final BytesData hash = rawTxData.sha3Data();

        final List<SignatureSingleData> signaturesData = new ArrayList<>(privateKeys.size());

        long ctx = NativeSecp256k1.contextCreate();
        try {
            for (final PrivateKey pk : privateKeys) {
                final NativeSecp256k1.RecoverableSignature signature = NativeSecp256k1.signRecoverableSerialized(ctx, charsToBytes(hash.getData()), pk.getBytes());
                final SignatureSingleData signatureData = new SignatureSingleData();
                signatureData.setSign(signature);
                signaturesData.add(signatureData);
            }
        } finally {
            // DON'T forget cleanup to avoid leaks
            NativeSecp256k1.contextCleanup(ctx);
        }

        mSignatureData = new SignatureMultiData();
        ((SignatureMultiData) mSignatureData).setSigns(signatureAddress, signaturesData);

        return new TransactionSign(new BytesData(encode(false)).toHexString());
    }

    public BytesData getUnsignedTxHash() {
        mSignatureType = Single;
        char[] encoded = encode(true);
        final BytesData rawTxData = new BytesData(encoded);
        return rawTxData.sha3Data();
    }

    public TransactionSign signExternal(SignatureSingleData signature) {
        mSignatureData = signature;
        return new TransactionSign(new BytesData(encode(false)).toHexString());
    }

    public TransactionSign signExternal(char[] r, char[] s, char[] v) {
        mSignatureData = new SignatureSingleData(r, s, v);
        return new TransactionSign(new BytesData(encode(false)).toHexString());
    }

    /**
     * Sign transaction data with single private key
     * @param privateKey private key data
     * @return {@link TransactionSign} Raw transaction sign
     * @since 0.3.0
     */
    public TransactionSign signSingle(@Nonnull final PrivateKey privateKey) {
        mSignatureType = Single;
        char[] encoded = encode(true);
        final BytesData rawTxData = new BytesData(encoded);
        final BytesData hash = rawTxData.sha3Data();

        NativeSecp256k1.RecoverableSignature signature;

        long ctx = NativeSecp256k1.contextCreate();
        try {
            signature = NativeSecp256k1.signRecoverableSerialized(ctx, charsToBytes(hash.getData()), privateKey.getBytes());
        } finally {
            // DON'T forget cleanup to avoid leaks
            NativeSecp256k1.contextCleanup(ctx);
        }

        if (signature == null) {
            return null;
        }

        mSignatureData = new SignatureSingleData();
        ((SignatureSingleData) mSignatureData).setSign(signature);

        return new TransactionSign(new BytesData(encode(false)).toHexString());
    }

    /**
     * Get transaction data
     * @param cls class to cast data object
     * @param <OpType> operation type
     * @return object extends {@link Operation}
     */
    public <OpType extends Operation> OpType getData(Class<OpType> cls) {
        return cls.cast(mOperationData);
    }

    @SuppressWarnings("unchecked")
    public <OpType extends Operation> OpType getData() {
        return (OpType) mOperationData;
    }

    <Op extends Operation> Transaction setData(Op operationData) {
        mOperationData = operationData;
        mType = operationData.getType();
        return this;
    }

    /**
     * Returns network id
     * @return
     */
    public BlockchainID getBlockchainId() {
        return mChainId;
    }

    public long getGasCoin() {
        return mGasCoin;//mGasCoin.replace("\0", "");
    }

    public BytesData getPayload() {
        return mPayload;
    }

    public String getPayloadString() {
        return new String(getPayload().getData());
    }


    char[] fromRawRlp(int idx, Object[] raw) {
        if (raw[idx] instanceof String) {
            return ((String) raw[idx]).toCharArray();
        }
        return (char[]) raw[idx];
    }

    /**
     * Object[] contains exact 10 elements
     * @param raw rlp encoded bytes array
     */
    void decodeRLP(Object[] raw) {
        mNonce = fixBigintSignedByte(raw[0]);
        mChainId = BlockchainID.valueOf(fixBigintSignedByte(fromRawRlp(1, raw)));
        mGasPrice = fixBigintSignedByte((raw[2]));
        mGasCoin = Long.valueOf(charsToString(fromRawRlp(3, raw), 10));
        mType = OperationType.findByValue(new BigInteger(charsToBytes(fromRawRlp(4, raw))));
        /**
         * ha, where is the 5th index?
         * see here: {@link #fromEncoded(String)}
         */
        mPayload = new BytesData(fromRawRlp(6, raw));
        mServiceData = new BytesData(fromRawRlp(7, raw));
        mSignatureType = SignatureType.findByValue(new BigInteger(charsToBytes(fromRawRlp(8, raw))));
        /**
         * And there's no 9 index, it's signature data
         * decoded here: {@link #fromEncoded(String)}
         */
    }

    char[] encode(boolean excludeSignature) {
        final char[] data = mOperationData.encodeRLP();

        if (excludeSignature) {
            return RLPBoxed.encode(new Object[]{
                    mNonce, BigInteger.valueOf(mChainId.getId()), mGasPrice, mGasCoin, mOperationData.getType().getValue(),
                    data,
                    mPayload.getData(),
                    mServiceData.getData(),
                    mSignatureType.getValue()
            });
        }

        final char[] signData = mSignatureData.encodeRLP();

        return RLPBoxed.encode(new Object[]{
                mNonce.toByteArray(), BigInteger.valueOf(mChainId.getId()), mGasPrice, mGasCoin, mOperationData.getType().getValue(),
                data,
                mPayload.getData(),
                mServiceData.getData(),
                mSignatureType.getValue(),
                signData
        });
    }

    FieldsValidationResult validate() {
        return new FieldsValidationResult("Invalid transaction data")
                .addResult("nonce", mNonce != null, "Nonce must be set")
//                .addResult("gasPrice", mGasCoin != null, "Gas coin must be set")
                .addResult("operationData", mOperationData !=
                        null, "Operation data does not set! Check your operation model.");
    }

    public static class Builder {
        private final Transaction mTx;
        private ExternalTransaction mExtTx = null;

        public Builder(BigInteger nonce, ExternalTransaction externalTransaction) {
            this(nonce);
            checkArgument(externalTransaction.getType() != null, "Transaction type must be set");
            checkArgument(externalTransaction.mOperationData != null, "Transaction data must be set");
            mTx.mType = externalTransaction.getType();
            mTx.mOperationData = externalTransaction.mOperationData;
            mTx.mPayload = firstNonNull(externalTransaction.getPayload(), new BytesData(new char[0]));
//            if (externalTransaction.getGasCoin() == null || externalTransaction.getGasCoin().equals("")) {
//                mTx.mGasCoin = MinterSDK.DEFAULT_COIN.id;//strrpad(10, MinterSDK.DEFAULT_COIN.symbol);
//            } else {
                mTx.mGasCoin = externalTransaction.getGasCoin();//strrpad(10, externalTransaction.getGasCoin());
//            }

            if (externalTransaction.getGasPrice() == null || externalTransaction.getGasPrice().equals(BigInteger.ZERO)) {
                mTx.mGasPrice = BigInteger.ONE;
            } else {
                mTx.mGasPrice = externalTransaction.getGasPrice();
            }

            mExtTx = externalTransaction;
        }

        /**
         * Init builder with transaction nonce. If you don't have it yet, set it later using {@link #setNonce(BigInteger)}
         * @param nonce transaction nonce
         */
        public Builder(BigInteger nonce) {
            checkArgument(nonce != null, "Nonce must be set");
            mTx = new Transaction(nonce);
            mTx.mChainId = BuildConfig.BLOCKCHAIN_ID;
        }

        public Transaction buildFromExternal() {
            if (mExtTx == null) {
                throw new IllegalStateException("Unable to build network tx without external transaction. Or build by yourself normal transaction.");
            }

            return mTx;
        }

        /**
         * Set network identifier for entire transaction. By default, it depends on choosed flavor,
         * but if you are using other then flavor network url, set it on your way.
         * DON't try to send testnet transaction ot mainnet or vise-versa, blockchain will return 115 error code anyway.
         * @param id network identifier
         * @return {@link Builder}
         * @see BlockchainID#MainNet
         * @see BlockchainID#TestNet
         */
        public Builder setBlockchainId(BlockchainID id) {
            mTx.mChainId = id;
            return this;
        }

        /**
         * Set fee coin. By default if not set, using {@link MinterSDK#DEFAULT_COIN}
         * @param coin string coin name. Min length: 3, maximum: 10
         * @return {@link Builder}
         */
        public Builder setGasCoin(long coin) {
            mTx.mGasCoin = coin;//strrpad(10, coin);
            return this;
        }

        /**
         * Set transaction gas, it useful for highly loaded network, by default, value is 1
         * @param gasPrice commission multiplier
         * @return {@link Builder}
         */
        public Builder setGasPrice(BigInteger gasPrice) {
            mTx.mGasPrice = gasPrice;
            return this;
        }

        /**
         * Set arbitrary user-defined bytes
         * @param data max size: 1024 bytes
         * @return {@link Builder}
         */
        public Builder setPayload(byte[] data) {
            return setPayload(new BytesData(data, true));
        }

        /**
         * Set arbitrary user-defined bytes
         * @param data max size: 1024 bytes
         * @return {@link Builder}
         */
        public Builder setPayload(BytesData data) {
            checkArgument(data.size() <= 1024, "Payload maximum size: 1024 bytes");
            mTx.mPayload = new BytesData(data.getData(), true);
            return this;
        }

        /**
         * Set arbitrary user-defined bytes
         * @param hexString max decoded size: 1024 bytes, means max string length should be 2048
         * @return {@link Builder}
         */
        public Builder setPayload(@Nonnull String hexString) {
            checkNotNull(hexString, "Hex data string can't be null");
            checkArgument(hexString.length() <= 2048, "Payload maximum size: 1024 bytes (2048 in hex string)");
            mTx.mPayload = new BytesData(hexString);
            return this;
        }

        /**
         * Set arbitrary user-defined bytes
         * @param byteBuffer max size: 1024 bytes
         * @return {@link Builder}
         */
        public Builder setPayload(ByteBuffer byteBuffer) {
            return setPayload(byteBuffer.array());
        }

        /**
         * Set transaction number. Calculation:
         * 1. get total num of transactions by address
         * 2. increment value
         * 3. you have nonce
         * @param nonce nonce value
         * @return {@link Builder}
         */
        public Builder setNonce(BigInteger nonce) {
            mTx.mNonce = nonce;
            return this;
        }

        /**
         * Create custom transaction builder, if (for example) you were forked minter blockchain and were created own transaction.
         * OR you can create dynamically any of existing transaction using just Class<?> object
         * @param operationClass
         * @param <Op>
         * @return
         */
        public <Op extends Operation> Op create(Class<Op> operationClass) {
            try {
                return operationClass.getDeclaredConstructor(Transaction.class).newInstance(mTx);
            } catch (InstantiationException e) {
                throw new RuntimeException(e);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e);
            } catch (NoSuchMethodException e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Create "Buy coin" transaction builder
         * @return {@link TxCoinBuy}
         */
        public TxCoinBuy buyCoin() {
            return new TxCoinBuy(mTx);
        }

        /**
         * Create "Sell coin" transaction builder
         * @return {@link TxCoinSell}
         */
        public TxCoinSell sellCoin() {
            return new TxCoinSell(mTx);
        }

        /**
         * Create "Sell all coins" transaction builder
         * @return {@link TxCoinSellAll}
         */
        public TxCoinSellAll sellAllCoins() {
            return new TxCoinSellAll(mTx);
        }

        /**
         * Create "Create coin" transaction builder
         * @return {@link TxCreateCoin}
         */
        public TxCreateCoin createCoin() {
            return new TxCreateCoin(mTx);
        }

        /**
         * Create "Declare candidacy" transaction builder
         * @return {@link TxDeclareCandidacy}
         */
        public TxDeclareCandidacy declareCandidacy() {
            return new TxDeclareCandidacy(mTx);
        }

        /**
         * Create "Delegate" transaction builder
         * @return {@link TxDelegate}
         */
        public TxDelegate delegate() {
            return new TxDelegate(mTx);
        }

        /**
         * Create "Check redeem" transaction builder
         * @return {@link TxRedeemCheck}
         */
        public TxRedeemCheck redeemCheck() {
            return new TxRedeemCheck(mTx);
        }

        /**
         * Create "Sending coin" transaction builder
         * @return {@link TxSendCoin}
         */
        public TxSendCoin sendCoin() {
            return new TxSendCoin(mTx);
        }

        /**
         * Create "Multiple signature" transaction builder
         * @return {@link TxCreateMultisigAddress}
         */
        public TxCreateMultisigAddress createMultisigAddress() {
            return new TxCreateMultisigAddress(mTx);
        }

        /**
         * Create "Multiple send coins" transaction builder
         * @return {@link TxMultisend}
         */
        public TxMultisend multiSend() {
            return new TxMultisend(mTx);
        }

        /**
         * Create "Validator candidate editing" transaction builder
         * @return {@link TxEditCandidate}
         */
        public TxEditCandidate editCandidate() {
            return new TxEditCandidate(mTx);
        }

        /**
         * Create "Make validator candidate offline" transaction builder
         * @return {@link TxSetCandidateOffline}
         */
        public TxSetCandidateOffline setCandidateOffline() {
            return new TxSetCandidateOffline(mTx);
        }

        /**
         * Create "Make validator candidate online" transaction builder
         * @return {@link TxSetCandidateOnline}
         */
        public TxSetCandidateOnline setCandidateOnline() {
            return new TxSetCandidateOnline(mTx);
        }

        /**
         * Create "Get back mo money!" transaction builder
         * @return {@link TxUnbound}
         */
        public TxUnbound unbound() {
            return new TxUnbound(mTx);
        }
    }

}
