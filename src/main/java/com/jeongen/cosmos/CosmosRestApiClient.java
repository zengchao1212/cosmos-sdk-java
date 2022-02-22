package com.jeongen.cosmos;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
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
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

import java.math.BigDecimal;
import java.math.BigInteger;

public class CosmosRestApiClient {

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

    public BigDecimal getBalanceInAtom(String address) {
        String path = String.format("/cosmos/bank/v1beta1/balances/%s/%s", address, this.token);
        QueryOuterClass.QueryBalanceResponse balanceResponse = client.get(path, QueryOuterClass.QueryBalanceResponse.class);
        if (balanceResponse.hasBalance()) {
            String amount = balanceResponse.getBalance().getAmount();
            return ATOMUnitUtil.microAtomToAtom(amount);
        } else {
            return BigDecimal.ZERO;
        }
    }

    public ServiceOuterClass.GetTxResponse getTx(String hash) {
        String path = String.format("/cosmos/tx/v1beta1/txs/%s", hash);
        return client.get(path, ServiceOuterClass.GetTxResponse.class);
    }

    public Query.GetLatestBlockResponse getLatestBlock() {
        String path = "/cosmos/base/tendermint/v1beta1/blocks/latest";
        return client.get(path, Query.GetLatestBlockResponse.class);
    }

    public Query.GetBlockByHeightResponse getBlockByHeight(Long height) {
        String path = String.format("/cosmos/base/tendermint/v1beta1/blocks/%d", height);
        return client.get(path, Query.GetBlockByHeightResponse.class);
    }

    public ServiceOuterClass.GetTxsEventResponse getTxsEventByHeight(Long height, String nextKey) {
        MultiValuedMap<String, String> queryMap = new ArrayListValuedHashMap<>();
        queryMap.put("events", "tx.height=" + height);
        queryMap.put("events", "message.action='send'");
        queryMap.put("pagination.key", nextKey);
        return client.get("/cosmos/tx/v1beta1/txs", queryMap, ServiceOuterClass.GetTxsEventResponse.class);
    }

    public QueryAccountResponse queryAccount(String address) {
        String path = String.format("/cosmos/auth/v1beta1/accounts/%s", address);
        return client.get(path, QueryAccountResponse.class);
    }

    public ServiceOuterClass.SimulateResponse simulate(ServiceOuterClass.SimulateRequest req) {
        String reqBody;
        try {
            reqBody = printer.print(req);
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }
        return client.post("/cosmos/tx/v1beta1/simulate", reqBody, ServiceOuterClass.SimulateResponse.class);
    }

    public ServiceOuterClass.SimulateResponse simulate(TxOuterClass.Tx tx) {
        ServiceOuterClass.SimulateRequest req = ServiceOuterClass.SimulateRequest.newBuilder()
                .setTx(tx)
                .build();
        return simulate(req);
    }

    public Auth.BaseAccount queryBaseAccount(String address) {
        QueryAccountResponse res = queryAccount(address);
        if (res.hasAccount() && res.getAccount().is(Auth.BaseAccount.class)) {
            try {
                return res.getAccount().unpack(Auth.BaseAccount.class);
            } catch (InvalidProtocolBufferException e) {
                throw new RuntimeException(e);
            }
        }
        throw new RuntimeException("account not found:" + address);
    }

    public ServiceOuterClass.BroadcastTxResponse broadcastTx(ServiceOuterClass.BroadcastTxRequest req) {
        String reqBody;
        try {
            reqBody = printer.print(req);
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }
        return client.post("/cosmos/tx/v1beta1/txs", reqBody, ServiceOuterClass.BroadcastTxResponse.class);
    }

    public long getLatestHeight() {
        Query.GetLatestBlockResponse latestBlock = getLatestBlock();
        return latestBlock.getBlock().getHeader().getHeight();
    }

    public TxOuterClass.Tx getTxRequest(String payerAddress, SendInfo sendInfo, Long seq, String memo) {
        TxOuterClass.TxBody.Builder txBodyBuilder = TxOuterClass.TxBody.newBuilder();
        TxOuterClass.AuthInfo.Builder authInfoBuilder = TxOuterClass.AuthInfo.newBuilder();

        TxOuterClass.Tx.Builder txBuilder = TxOuterClass.Tx.newBuilder();

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

        authInfoBuilder.addSignerInfos(getSignInfo(payerAddress, seq));

        CoinOuterClass.Coin feeCoin = CoinOuterClass.Coin.newBuilder()
                .setAmount(ATOMUnitUtil.atomToMicroAtom(new BigDecimal("0.000001")).toPlainString())
                .setDenom(this.token)
                .build();

        TxOuterClass.Fee fee = TxOuterClass.Fee.newBuilder()
                .setGasLimit(80000)
                .setPayer("")
                .addAmount(feeCoin)
                .build();

        authInfoBuilder.setFee(fee);
        if (memo != null && !memo.isEmpty()) {
            txBodyBuilder.setMemo(memo);
        }
        TxOuterClass.TxBody txBody = txBodyBuilder.build();

        TxOuterClass.AuthInfo authInfo = authInfoBuilder.build();
        txBuilder.addSignatures(ByteString.copyFrom(new byte[64]));

        txBuilder.setBody(txBody);
        txBuilder.setAuthInfo(authInfo);
        return txBuilder.build();
    }

    public TxOuterClass.Tx send(String payerAddress, SendInfo sendInfo, Long seq, String memo) {

        TxOuterClass.Tx tx = getTxRequest(payerAddress, sendInfo, seq, memo);
        Abci.GasInfo gasInfo = simulate(tx).getGasInfo();
        TxOuterClass.Fee fee = tx.getAuthInfo().getFee().toBuilder().setGasLimit(gasInfo.getGasUsed() + 20000).build();
        TxOuterClass.AuthInfo authInfo = tx.getAuthInfo().toBuilder().setFee(fee).build();
        return tx.toBuilder().setAuthInfo(authInfo).build();
    }

    public TxOuterClass.Tx sign(TxOuterClass.Tx tx, byte[] ecKey) {
        CosmosCredentials credentials = CosmosCredentials.create(ecKey);
        TxOuterClass.AuthInfo authInfo = tx.getAuthInfo().toBuilder().setSignerInfos(0, getSignInfo(credentials)).build();
        return tx.toBuilder().setAuthInfo(authInfo).setSignatures(0, getSignBytes(credentials, tx.getBody(), authInfo)).build();
    }


    public String broad(TxOuterClass.Tx tx) throws Exception {
        ServiceOuterClass.BroadcastTxRequest broadcastTxRequest = ServiceOuterClass.BroadcastTxRequest.newBuilder()
                .setTxBytes(tx.toByteString())
                .setMode(ServiceOuterClass.BroadcastMode.BROADCAST_MODE_SYNC)
                .build();

        ServiceOuterClass.BroadcastTxResponse broadcastTxResponse = broadcastTx(broadcastTxRequest);

        if (!broadcastTxResponse.hasTxResponse()) {
            throw new Exception("broadcastTxResponse no body\n" + printer.print(tx));
        }
        Abci.TxResponse txResponse = broadcastTxResponse.getTxResponse();
        if (txResponse.getCode() != 0 || !StringUtil.isNullOrEmpty(txResponse.getCodespace())) {
            throw new Exception("BroadcastTx error:" + txResponse.getCodespace() + "," + txResponse.getCode() + "," + txResponse.getRawLog() + "\n" + printer.print(tx));
        }
        if (txResponse.getTxhash().length() != 64) {
            throw new Exception("Txhash illegal\n" + printer.print(tx));
        }
        return txResponse.getTxhash();
    }

    public TxOuterClass.SignerInfo getSignInfo(CosmosCredentials credentials) {
        byte[] encodedPubKey = credentials.getEcKey().getPubKeyPoint().getEncoded(true);
        Keys.PubKey pubKey = Keys.PubKey.newBuilder()
                .setKey(ByteString.copyFrom(encodedPubKey))
                .build();
        TxOuterClass.ModeInfo.Single single = TxOuterClass.ModeInfo.Single.newBuilder()
                .setMode(Signing.SignMode.SIGN_MODE_DIRECT)
                .build();

        Auth.BaseAccount baseAccount = queryBaseAccount(credentials.getAddress());
        return TxOuterClass.SignerInfo.newBuilder()
                .setPublicKey(Any.pack(pubKey, "/"))
                .setModeInfo(TxOuterClass.ModeInfo.newBuilder().setSingle(single))
                .setSequence(baseAccount.getSequence())
                .build();
    }

    public TxOuterClass.SignerInfo getSignInfo(String payerAddress, Long seq) {
        byte[] encodedPubKey = ECKey.fromPrivate(BigInteger.valueOf(999999)).getPubKeyPoint().getEncoded(true);
        Keys.PubKey pubKey = Keys.PubKey.newBuilder()
                .setKey(ByteString.copyFrom(encodedPubKey))
                .build();
        TxOuterClass.ModeInfo.Single single = TxOuterClass.ModeInfo.Single.newBuilder()
                .setMode(Signing.SignMode.SIGN_MODE_DIRECT)
                .build();

        Auth.BaseAccount baseAccount = queryBaseAccount(payerAddress);
        return TxOuterClass.SignerInfo.newBuilder()
                .setPublicKey(Any.pack(pubKey, "/"))
                .setModeInfo(TxOuterClass.ModeInfo.newBuilder().setSingle(single))
                .setSequence(seq == null ? baseAccount.getSequence() : seq)
                .build();
    }

    public ByteString getSignBytes(CosmosCredentials credentials, TxOuterClass.TxBody txBody, TxOuterClass.AuthInfo authInfo) {
        Auth.BaseAccount baseAccount = queryBaseAccount(credentials.getAddress());
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
