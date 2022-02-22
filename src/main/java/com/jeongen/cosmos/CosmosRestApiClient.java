package com.jeongen.cosmos;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import com.jeongen.cosmos.crypro.CosmosCredentials;
import com.jeongen.cosmos.util.ATOMUnitUtil;
import com.jeongen.cosmos.util.JsonToProtoObjectUtil;
import com.jeongen.cosmos.vo.SendInfo;
import cosmos.auth.v1beta1.Auth;
import cosmos.auth.v1beta1.QueryOuterClass.QueryAccountResponse;
import cosmos.bank.v1beta1.QueryOuterClass;
import cosmos.bank.v1beta1.Tx;
import cosmos.base.abci.v1beta1.Abci;
import cosmos.base.tendermint.v1beta1.Query;
import cosmos.base.v1beta1.CoinOuterClass;
import cosmos.crypto.secp256k1.Keys;
import cosmos.tx.signing.v1beta1.Signing;
import cosmos.tx.v1beta1.ServiceOuterClass;
import cosmos.tx.v1beta1.TxOuterClass;
import io.netty.util.internal.StringUtil;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CosmosRestApiClient {

    private static final Logger logger = LoggerFactory.getLogger(CosmosRestApiClient.class);

    private static final JsonFormat.Printer printer = JsonToProtoObjectUtil.getPrinter();

    private final GaiaHttpClient client;

    /**
     * 代币名称
     * 主网：uatom
     * 测试网：stake
     */
    private final String token;

    /**
     * API /node_info 的 network 字段
     * 测试网：cosmoshub-testnet
     * 主网：cosmoshub-4
     */
    private final String chainId;

    public CosmosRestApiClient(String baseUrl, String chainId, String token) {
        this.client = new GaiaHttpClient(baseUrl);
        this.token = token;
        this.chainId = chainId;
    }

    public BigDecimal getBalanceInAtom(String address) throws Exception {
        String path = String.format("/cosmos/bank/v1beta1/balances/%s/%s", address, this.token);
        QueryOuterClass.QueryBalanceResponse balanceResponse = client.get(path, QueryOuterClass.QueryBalanceResponse.class);
        if (balanceResponse.hasBalance()) {
            String amount = balanceResponse.getBalance().getAmount();
            return ATOMUnitUtil.microAtomToAtom(amount);
        } else {
            return BigDecimal.ZERO;
        }
    }

    public ServiceOuterClass.GetTxResponse getTx(String hash) throws Exception {
        String path = String.format("/cosmos/tx/v1beta1/txs/%s", hash);
        return client.get(path, ServiceOuterClass.GetTxResponse.class);
    }

    public Query.GetLatestBlockResponse getLatestBlock() throws Exception {
        String path = "/cosmos/base/tendermint/v1beta1/blocks/latest";
        return client.get(path, Query.GetLatestBlockResponse.class);
    }

    public Query.GetBlockByHeightResponse getBlockByHeight(Long height) throws Exception {
        String path = String.format("/cosmos/base/tendermint/v1beta1/blocks/%d", height);
        return client.get(path, Query.GetBlockByHeightResponse.class);
    }

    public ServiceOuterClass.GetTxsEventResponse getTxsEventByHeight(Long height, String nextKey) throws Exception {
        MultiValuedMap<String, String> queryMap = new ArrayListValuedHashMap<>();
        queryMap.put("events", "tx.height=" + height);
        queryMap.put("events", "message.action='send'");
        queryMap.put("pagination.key", nextKey);
        ServiceOuterClass.GetTxsEventResponse eventResponse = client.get("/cosmos/tx/v1beta1/txs", queryMap, ServiceOuterClass.GetTxsEventResponse.class);
        return eventResponse;
    }

    public QueryAccountResponse queryAccount(String address) throws Exception {
        String path = String.format("/cosmos/auth/v1beta1/accounts/%s", address);
        return client.get(path, QueryAccountResponse.class);
    }

    public Auth.BaseAccount queryBaseAccount(String address, Map<String, Auth.BaseAccount> cacheMap) throws Exception {
        if (cacheMap.containsKey(address)) {
            return cacheMap.get(address);
        }
        Auth.BaseAccount baseAccount = queryBaseAccount(address);
        cacheMap.put(address, baseAccount);
        return baseAccount;
    }

    public ServiceOuterClass.SimulateResponse simulate(ServiceOuterClass.SimulateRequest req) throws Exception {
        String reqBody = printer.print(req);
        ServiceOuterClass.SimulateResponse simulateResponse = client.post("/cosmos/tx/v1beta1/simulate", reqBody, ServiceOuterClass.SimulateResponse.class);
        return simulateResponse;
    }

    public ServiceOuterClass.SimulateResponse simulate(TxOuterClass.Tx tx) throws Exception {
        ServiceOuterClass.SimulateRequest req = ServiceOuterClass.SimulateRequest.newBuilder()
                .setTx(tx)
                .build();
        return simulate(req);
    }

    public Auth.BaseAccount queryBaseAccount(String address) throws Exception {
        QueryAccountResponse res = queryAccount(address);
        if (res.hasAccount() && res.getAccount().is(Auth.BaseAccount.class)) {
            return res.getAccount().unpack(Auth.BaseAccount.class);
        }
        throw new RuntimeException("account not found:" + address);
    }

    public ServiceOuterClass.BroadcastTxResponse broadcastTx(ServiceOuterClass.BroadcastTxRequest req) throws Exception {
        String reqBody = printer.print(req);
        ServiceOuterClass.BroadcastTxResponse broadcastTxResponse = client.post("/cosmos/tx/v1beta1/txs", reqBody, ServiceOuterClass.BroadcastTxResponse.class);
        return broadcastTxResponse;
    }

    public long getLatestHeight() throws Exception {
        Query.GetLatestBlockResponse latestBlock = getLatestBlock();
        return latestBlock.getBlock().getHeader().getHeight();
    }

    public TxOuterClass.Tx getTxRequest(String payerAddress, List<SendInfo> sendList, BigDecimal feeInAtom, long gasLimit) throws Exception {
        Map<String, Auth.BaseAccount> baseAccountCache = new HashMap<>();
        TxOuterClass.TxBody.Builder txBodyBuilder = TxOuterClass.TxBody.newBuilder();
        TxOuterClass.AuthInfo.Builder authInfoBuilder = TxOuterClass.AuthInfo.newBuilder();

        TxOuterClass.Tx.Builder txBuilder = TxOuterClass.Tx.newBuilder();
        for (SendInfo sendInfo : sendList) {
            BigInteger sendAmountInMicroAtom = ATOMUnitUtil.atomToMicroAtomBigInteger(sendInfo.getAmountInAtom());
            CoinOuterClass.Coin sendCoin = CoinOuterClass.Coin.newBuilder()
                    .setAmount(sendAmountInMicroAtom.toString())
                    .setDenom(this.token)
                    .build();

            Tx.MsgSend message = Tx.MsgSend.newBuilder()
                    .setFromAddress(payerAddress)
                    .setToAddress(sendInfo.getToAddress())
                    .addAmount(sendCoin)
                    .build();

            txBodyBuilder.addMessages(Any.pack(message, "/"));
        }
        authInfoBuilder.addSignerInfos(getSignInfo(payerAddress));

        CoinOuterClass.Coin feeCoin = CoinOuterClass.Coin.newBuilder()
                .setAmount(ATOMUnitUtil.atomToMicroAtom(feeInAtom).toPlainString())
                .setDenom(this.token)
                .build();

        TxOuterClass.Fee fee = TxOuterClass.Fee.newBuilder()
                .setGasLimit(gasLimit)
                .setPayer("")
                .addAmount(feeCoin)
                .build();

        authInfoBuilder.setFee(fee);

        TxOuterClass.TxBody txBody = txBodyBuilder.build();

        TxOuterClass.AuthInfo authInfo = authInfoBuilder.build();

        txBuilder.addSignatures(ByteString.copyFrom(new byte[64]));

        txBuilder.setBody(txBody);
//        txBuilder.setAuthInfo(authInfo);
        TxOuterClass.Tx tx = txBuilder.build();
        return tx;
    }

    /**
     * 发送交易
     *
     * @param payerAddress 支付账户
     * @param sendList         转账列表
     * @return 交易哈希
     * @throws Exception API 错误
     */
    public TxOuterClass.Tx sendMultiTx(String payerAddress, List<SendInfo> sendList) throws Exception {
        if (sendList == null || sendList.size() == 0) {
            throw new Exception("sendList is empty");
        }

        TxOuterClass.Tx tx = getTxRequest(payerAddress, sendList, BigDecimal.ONE, 1);
        Abci.GasInfo gasInfo=simulate(tx).getGasInfo();
//        tx.toBuilder().m;
        return null;
    }

    public TxOuterClass.SignerInfo getSignInfo(CosmosCredentials credentials) throws Exception {
        byte[] encodedPubKey = credentials.getEcKey().getPubKeyPoint().getEncoded(true);
        Keys.PubKey pubKey = Keys.PubKey.newBuilder()
                .setKey(ByteString.copyFrom(encodedPubKey))
                .build();
        TxOuterClass.ModeInfo.Single single = TxOuterClass.ModeInfo.Single.newBuilder()
                .setMode(Signing.SignMode.SIGN_MODE_DIRECT)
                .build();

        Auth.BaseAccount baseAccount = queryBaseAccount(credentials.getAddress());
        TxOuterClass.SignerInfo signerInfo = TxOuterClass.SignerInfo.newBuilder()
                .setPublicKey(Any.pack(pubKey, "/"))
                .setModeInfo(TxOuterClass.ModeInfo.newBuilder().setSingle(single))
                .setSequence(baseAccount.getSequence())
                .build();
        return signerInfo;
    }

    public TxOuterClass.SignerInfo getSignInfo(String address) throws Exception {
        byte[] encodedPubKey = ECKey.fromPrivate(Hex.decode("2d3f950aec4ab81da54bde1e2ac6309deccbc6443bfc0a91da15dc12c3eb96dd")).getPubKeyPoint().getEncoded(true);
        Keys.PubKey pubKey = Keys.PubKey.newBuilder()
                .setKey(ByteString.copyFrom(encodedPubKey))
                .build();
        TxOuterClass.ModeInfo.Single single = TxOuterClass.ModeInfo.Single.newBuilder()
                .setMode(Signing.SignMode.SIGN_MODE_DIRECT)
                .build();

        Auth.BaseAccount baseAccount = queryBaseAccount(address);
        TxOuterClass.SignerInfo signerInfo = TxOuterClass.SignerInfo.newBuilder()
                .setPublicKey(Any.pack(pubKey, "/"))
                .setModeInfo(TxOuterClass.ModeInfo.newBuilder().setSingle(single))
                .setSequence(baseAccount.getSequence())
                .build();
        return signerInfo;
    }

    public ByteString getSignBytes(CosmosCredentials credentials, TxOuterClass.TxBody txBody, TxOuterClass.AuthInfo authInfo, Map<String, Auth.BaseAccount> baseAccountCache) throws Exception {
        Auth.BaseAccount baseAccount = queryBaseAccount(credentials.getAddress(), baseAccountCache);
        byte[] sigBytes = signDoc(credentials.getEcKey().getPrivKeyBytes(), baseAccount, txBody, authInfo, this.chainId);
        return ByteString.copyFrom(sigBytes);
    }

    public static byte[] signDoc(byte[] privateKey, Auth.BaseAccount baseAccount, TxOuterClass.TxBody txBody, TxOuterClass.AuthInfo authInfo, String chainId) {
        ECKeyPair keyPair = ECKeyPair.create(privateKey);
        TxOuterClass.SignDoc signDoc = TxOuterClass.SignDoc.newBuilder()
                .setBodyBytes(txBody.toByteString())
                .setAuthInfoBytes(authInfo.toByteString())
                .setAccountNumber(baseAccount.getAccountNumber())
                .setChainId(chainId)
                .build();
        byte[] hash = Sha256Hash.hash(signDoc.toByteArray());
        Sign.SignatureData signature = Sign.signMessage(hash, keyPair, false);
        return mergeBytes(signature.getR(), signature.getS());
    }

    private static byte[] mergeBytes(byte[] array1, byte[] array2) {
        byte[] joinedArray = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, joinedArray, 0, array1.length);
        System.arraycopy(array2, 0, joinedArray, array1.length, array2.length);
        return joinedArray;
    }
}
