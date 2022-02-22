package com.jeongen.cosmos;

import com.jeongen.cosmos.crypro.CosmosCredentials;
import com.jeongen.cosmos.vo.SendInfo;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

public class CosmosRestApiClientTest extends TestCase {

    public void testSendMultiTx() throws Exception {
        CosmosRestApiClient cosmosRestApiClient = new CosmosRestApiClient("https://atom.getblock.io/mainnet/?api_key=3faec599-5ff3-498f-a217-efd338b8ec92", "cosmoshub-4", "uatom");
        // 私钥生成公钥、地址
        byte[] privateKey = Hex.decode("c2ad7a31c06ea8bb560a0467898ef844523f2f804dec96fedf65906dbb951f24");
        CosmosCredentials credentials = CosmosCredentials.create(privateKey);
        // 获取地址
        System.out.println("address:" + credentials.getAddress());
        List<SendInfo> sendList = new ArrayList<>();
        sendList.add(SendInfo.builder().toAddress("cosmos12kd7gu4lamw29pv4u6ug8aryr0p7wm207uwt30").amountInAtom(new BigDecimal("0.0001")).build());
//        sendList.add(SendInfo.builder().credentials(credentials).toAddress("cosmos1u3zluamfx5pvgha0dn73ah4pyu9ckv6scvdw72").amountInAtom(new BigDecimal("0.0001")).build());
//        // 生成、签名、广播交易
        cosmosRestApiClient.sendMultiTx("cosmos1f74nxgxpequqmpqemdfz5dhr2sf873ydptxhrg", sendList);
//        System.out.println(txResponse);
//
//        // 获取指定高度的交易
//        ServiceOuterClass.GetTxsEventResponse txsEventByHeight = cosmosRestApiClient.getTxsEventByHeight(6900000L, "");
    }
}