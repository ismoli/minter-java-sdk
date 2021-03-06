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




import java.math.BigDecimal;
import java.math.BigInteger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import network.minter.core.internal.helpers.StringHelper;
import network.minter.core.util.DecodeResult;
import network.minter.core.util.RLPBoxed;

import static network.minter.core.internal.helpers.BytesHelper.fixBigintSignedByte;
import static network.minter.core.internal.helpers.StringHelper.charsToString;

/**
 * minter-android-blockchain. 2018
 * @author Eduard Maximovich <edward.vstock@gmail.com>
 */
public final class TxCoinBuy extends Operation {

    private Long mCoinToBuy;
    private BigInteger mValueToBuy;
    private Long mCoinToSell;
    private BigInteger mMaxValueToSell;

    public TxCoinBuy() {
    }

    public TxCoinBuy(Transaction rawTx) {
        super(rawTx);
    }



    public Long getCoinToBuy() {
        return mCoinToBuy;//.replace("\0", "");
    }

    public TxCoinBuy setCoinToBuy(long coin) {
        mCoinToBuy = coin;//StringHelper.strrpad(10, coin.toUpperCase());
        return this;
    }

    public Long getCoinToSell() {
        return mCoinToSell;//.replace("\0", "");
    }

    public TxCoinBuy setCoinToSell(long coin) {
        mCoinToSell = coin;//StringHelper.strrpad(10, coin.toUpperCase());
        return this;
    }

    public BigDecimal getMaxValueToSell() {
        return Transaction.humanizeValue(mMaxValueToSell);
    }

    /**
     * Original value in bigint format
     * @return origin value
     */
    public BigInteger getValueToBuyBigInteger() {
        return mValueToBuy;
    }

    public TxCoinBuy setMaxValueToSell(@Nonnull final CharSequence decimalValue) {
        return setMaxValueToSell(new BigDecimal(decimalValue.toString()));
    }

    public TxCoinBuy setValueToBuy(BigInteger amount) {
        mValueToBuy = amount;
        return this;
    }

    public TxCoinBuy setMaxValueToSell(BigDecimal amount) {
        return setMaxValueToSell(Transaction.normalizeValue(amount));
    }

    /**
     * Normalized original value in BigDecimal format
     * @return BigDecimal value
     */
    public BigDecimal getValueToBuy() {
        return Transaction.humanizeValue(mValueToBuy);
    }

    public TxCoinBuy setMaxValueToSell(BigInteger amount) {
        mMaxValueToSell = amount;
        return this;
    }

    public TxCoinBuy setValueToBuy(BigDecimal amount) {
        return setValueToBuy(Transaction.normalizeValue(amount));
    }

    public TxCoinBuy setValueToBuy(@Nonnull final CharSequence decimalValue) {
        return setValueToBuy(new BigDecimal(decimalValue.toString()));
    }

    @Override
    public OperationType getType() {
        return OperationType.BuyCoin;
    }

    @Nullable
    @Override
    protected FieldsValidationResult validate() {
        return new FieldsValidationResult()
                .addResult("mCoinToBuy", mCoinToBuy != null, "Coin length must be from 3 to 10 chars")
                .addResult("mCoinToSell", mCoinToSell != null, "Coin length must be from 3 to 10 chars")
                .addResult("mValueToBuy", mValueToBuy != null, "Value must be set")
                .addResult("mMaxValueToSell", mMaxValueToSell != null, "Maximum value to sell must be set");
    }

    @Nonnull
    @Override
    protected char[] encodeRLP() {
	    return RLPBoxed.encode(new Object[]{
                mCoinToBuy,
                mValueToBuy,
                mCoinToSell,
                mMaxValueToSell
        });
    }

    @Override
    protected void decodeRLP(@Nonnull char[] rlpEncodedData) {
	    final DecodeResult rlp = RLPBoxed.decode(rlpEncodedData, 0);/**/
        final Object[] decoded = (Object[]) rlp.getDecoded();

	    mCoinToBuy = Long.valueOf(charsToString(fromRawRlp(0, decoded)));
        mValueToBuy = fixBigintSignedByte(fromRawRlp(1, decoded));
	    mCoinToSell = Long.valueOf(charsToString(fromRawRlp(2, decoded)));
        mMaxValueToSell = fixBigintSignedByte(fromRawRlp(3, decoded));
    }
}
