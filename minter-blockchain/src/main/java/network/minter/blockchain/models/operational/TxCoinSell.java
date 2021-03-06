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

import network.minter.core.util.DecodeResult;
import network.minter.core.util.RLPBoxed;

import static network.minter.blockchain.models.operational.Transaction.normalizeValue;
import static network.minter.core.internal.helpers.BytesHelper.fixBigintSignedByte;
import static network.minter.core.internal.helpers.StringHelper.charsToString;
import static network.minter.core.internal.helpers.StringHelper.strrpad;

/**
 * minter-android-blockchain. 2018
 * @author Eduard Maximovich <edward.vstock@gmail.com>
 */
public final class TxCoinSell extends Operation {

    private Long mCoinToSell;
    private BigInteger mValueToSell;
    private Long mCoinToBuy;
    private BigInteger mMinValueToBuy;

    public TxCoinSell() {
    }

    public TxCoinSell(Transaction rawTx) {
        super(rawTx);
    }


    public Long getCoinToSell() {
        return mCoinToSell;//.replace("\0", "");
    }

    public TxCoinSell setCoinToSell(long coin) {
        mCoinToSell = coin;//strrpad(10, coin.toUpperCase());
        return this;
    }

    public Long getCoinToBuy() {
        return mCoinToBuy;//.replace("\0", "");
    }

    public TxCoinSell setCoinToBuy(long coin) {
        mCoinToBuy = coin;//strrpad(10, coin.toUpperCase());
        return this;
    }

    public BigDecimal getMinValueToBuy() {
        return Transaction.humanizeValue(mMinValueToBuy);
    }

    public BigInteger getValueToSellBigInteger() {
        return mValueToSell;
    }

    public TxCoinSell setMinValueToBuy(BigDecimal amount) {
        return setMinValueToBuy(normalizeValue(amount));
    }

    public TxCoinSell setValueToSell(BigInteger amount) {
        mValueToSell = amount;
        return this;
    }

    public TxCoinSell setMinValueToBuy(@Nonnull final CharSequence decimalValue) {
        return setMinValueToBuy(new BigDecimal(decimalValue.toString()));
    }

    public BigDecimal getValueToSell() {
        return Transaction.humanizeValue(mValueToSell);
    }

    public TxCoinSell setValueToSell(@Nonnull final CharSequence decimalValue) {
        return setValueToSell(new BigDecimal(decimalValue.toString()));
    }

    public TxCoinSell setMinValueToBuy(BigInteger amount) {
        mMinValueToBuy = amount;
        return this;
    }

    public TxCoinSell setValueToSell(BigDecimal amount) {
        return setValueToSell(normalizeValue(amount));
    }

    @Override
    public OperationType getType() {
        return OperationType.SellCoin;
    }

    @Nullable
    @Override
    protected FieldsValidationResult validate() {
        return new FieldsValidationResult()
                .addResult("mCoinToBuy", mCoinToBuy != null, "Coin length must be from 3 to 10 chars")
                .addResult("mCoinToSell", mCoinToSell != null , "Coin length must be from 3 to 10 chars")
                .addResult("mValueToSell", mValueToSell != null, "Value must be set")
                .addResult("mMinValueToBuy", mMinValueToBuy != null, "Minimum value to buy must be set");
    }

    @Nonnull
    @Override
    protected char[] encodeRLP() {
	    return RLPBoxed.encode(new Object[]{
                mCoinToSell,
                mValueToSell,
                mCoinToBuy,
                mMinValueToBuy
        });
    }

    @Override
    protected void decodeRLP(@Nonnull char[] rlpEncodedData) {
	    final DecodeResult rlp = RLPBoxed.decode(rlpEncodedData, 0);/**/
        final Object[] decoded = (Object[]) rlp.getDecoded();

	    mCoinToSell = Long.valueOf(charsToString(fromRawRlp(0, decoded)));
        mValueToSell = fixBigintSignedByte(fromRawRlp(1, decoded));
	    mCoinToBuy = Long.valueOf(charsToString(fromRawRlp(2, decoded)));
        mMinValueToBuy = fixBigintSignedByte(fromRawRlp(3, decoded));
    }
}
