/*
 * Copyright (C) by MinterTeam. 2019
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

package network.minter.explorer.tests.repo;


import org.junit.Test;
import org.parceler.Parcels;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;

import network.minter.blockchain.models.ExchangeBuyValue;
import network.minter.blockchain.models.ExchangeSellValue;
import network.minter.blockchain.models.operational.Transaction;
import network.minter.core.internal.log.StdLogger;
import network.minter.explorer.MinterExplorerApi;
import network.minter.explorer.models.CoinItem;
import network.minter.explorer.models.ExpResult;
import network.minter.explorer.models.GateResult;
import network.minter.explorer.repo.ExplorerCoinsRepository;
import network.minter.explorer.repo.GateEstimateRepository;
import retrofit2.Response;

import static java.math.BigDecimal.ZERO;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * minter-android-explorer. 2019
 *
 * @author Eduard Maximovich [edward.vstock@gmail.com]
 */
public class CoinsRepositoryTest extends BaseRepoTest {

    static {
        MinterExplorerApi.initialize(true, new StdLogger());
//        MinterExplorerApi.getInstance().getApiService().addHttpInterceptor(new ApiMockInterceptor());
    }

    @SuppressWarnings("SimplifiableJUnitAssertion")
    @Test
    public void getAll() throws IOException {
        ExplorerCoinsRepository repo = MinterExplorerApi.getInstance().coins();

        Response<ExpResult<List<CoinItem>>> result = repo.getAll().execute();
        checkResponseSuccess(result);

        assertNotNull(result.body());
        List<CoinItem> items = result.body().result;
        assertNotNull(items);
        assertEquals(44, items.size());

        CoinItem item0 = items.get(0);
        assertNotNull(item0);

        assertEquals("MNT", item0.symbol);
        assertEquals("", item0.name);
        assertEquals(0, item0.crr);
        assertTrue(ZERO.compareTo(item0.reserveBalance) == 0);
        assertTrue(ZERO.compareTo(item0.volume) == 0);

        CoinItem item1 = items.get(items.size() - 1);
        assertNotNull(item1);

        assertEquals("CINEMACOIN", item1.symbol);
        assertEquals("CINEMACOIN", item1.name);
        assertEquals(10, item1.crr);
        assertEquals(new BigDecimal("100000.000000000000000000"), item1.volume);
        assertEquals(new BigDecimal("100.000000000000000000"), item1.reserveBalance);

//        Parcelable s = Parcels.wrap(item1);
//        CoinItem us = Parcels.unwrap(s);
    }

    @Test
    public void getCinemacoin() throws IOException {
        ExplorerCoinsRepository repo = MinterExplorerApi.getInstance().coins();

        Response<ExpResult<List<CoinItem>>> result = repo.search("cinemacoin").execute();
        checkResponseSuccess(result);

        assertNotNull(result.body());
        List<CoinItem> items = result.body().result;
        assertNotNull(items);
        assertEquals(1, items.size());


        CoinItem item0 = items.get(0);
        assertNotNull(item0);

        assertEquals("CINEMACOIN", item0.symbol);
        assertEquals("CINEMACOIN", item0.name);
        assertEquals(10, item0.crr);
        assertEquals(new BigDecimal("100.000000000000000000"), item0.reserveBalance);
        assertEquals(new BigDecimal("100000.000000000000000000"), item0.volume);
    }

    @Test
    public void getUnknownCoin() throws IOException {
        ExplorerCoinsRepository repo = MinterExplorerApi.getInstance().coins();

        Response<ExpResult<List<CoinItem>>> result = repo.search("unknown").execute();
        checkResponseSuccess(result);

        assertNotNull(result.body());
        List<CoinItem> items = result.body().result;
        assertNotNull(items);
        assertEquals(0, items.size());
    }

    @Test
    public void buyCoinCurrency() throws IOException {
        GateEstimateRepository repo = MinterExplorerApi.getInstance().estimate();
        Response<GateResult<ExchangeBuyValue>> result =
                repo.getCoinExchangeCurrencyToBuy("MNT", new BigDecimal("1"), "CINEMACOIN").execute();

        checkResponseSuccess(result);
        assertNotNull(result.body());
        ExchangeBuyValue data = result.body().result;
        assertNotNull(data);

        assertEquals(new BigInteger("25561747758752620"), data.willPay);
        assertEquals(new BigInteger("100000000000000000"), data.commission);
        assertEquals(new BigDecimal("100000000000000000").divide(Transaction.VALUE_MUL_DEC), data.getCommission());
        assertEquals(new BigDecimal("25561747758752620").divide(Transaction.VALUE_MUL_DEC), data.getAmount());
        assertEquals(
                new BigDecimal("100000000000000000").divide(Transaction.VALUE_MUL_DEC)
                        .add(new BigDecimal("25561747758752620").divide(Transaction.VALUE_MUL_DEC))
                ,
                data.getAmountWithCommission()
        );
    }

    @Test
    public void buyCoinWrongName() throws IOException {
        GateEstimateRepository repo = MinterExplorerApi.getInstance().estimate();
        Response<GateResult<ExchangeBuyValue>> result =
                repo.getCoinExchangeCurrencyToBuy("MNT", new BigDecimal("1"), "MNT").execute();

        checkResponseError(result);
        assertNotNull(result.body());
        GateResult.ErrorResult error = result.body().error;
        assertNull(error);
        // hmm...
//        assertNotEquals("\"From\" coin equals to \"to\" coin", error.getMessage());
//        assertEquals(BCResult.ResultCode.UnknownError, error.getResultCode());
    }

    @Test
    public void sellCoinCurrency() throws IOException {
        GateEstimateRepository repo = MinterExplorerApi.getInstance().estimate();
        Response<GateResult<ExchangeSellValue>> result =
                repo.getCoinExchangeCurrencyToSell("MNT", new BigDecimal("1"), "CINEMACOIN").execute();

        checkResponseSuccess(result);
        assertNotNull(result.body());
        ExchangeSellValue data = result.body().result;
        assertNotNull(data);

        assertEquals(new BigInteger("39060624404202783670"), data.willGet);
        assertEquals(new BigInteger("100000000000000000"), data.commission);
        assertEquals(new BigDecimal("100000000000000000").divide(Transaction.VALUE_MUL_DEC), data.getCommission());
        assertEquals(new BigDecimal("39060624404202783670").divide(Transaction.VALUE_MUL_DEC), data.getAmount());
        assertEquals(
                new BigDecimal("100000000000000000").divide(Transaction.VALUE_MUL_DEC)
                        .add(new BigDecimal("39060624404202783670").divide(Transaction.VALUE_MUL_DEC))
                ,
                data.getAmountWithCommission()
        );
    }

    @Test
    public void sellCoinWrongName() throws IOException {
        GateEstimateRepository repo = MinterExplorerApi.getInstance().estimate();
        Response<GateResult<ExchangeSellValue>> result =
                repo.getCoinExchangeCurrencyToSell("MNT", new BigDecimal("1"), "MNT").execute();

        checkResponseError(result);
        assertNotNull(result.body());
        GateResult.ErrorResult error = result.body().error;
        assertNull(error);
//        assertEquals("\"From\" coin equals to \"to\" coin", error.getMessage());
//        assertEquals(BCResult.ResultCode.UnknownError, error.getResultCode());
    }
}
