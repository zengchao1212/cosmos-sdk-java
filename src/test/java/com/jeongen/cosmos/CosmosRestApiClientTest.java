package com.jeongen.cosmos;

import com.jeongen.cosmos.crypro.CosmosCredentials;
import com.jeongen.cosmos.vo.SendInfo;
import cosmos.tx.v1beta1.TxOuterClass;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigDecimal;

public class CosmosRestApiClientTest extends TestCase {

    public void testSendMultiTx() throws Exception {
        CosmosRestApiClient cosmosRestApiClient = new CosmosRestApiClient("https://atom.getblock.io/mainnet/?api_key=3faec599-5ff3-498f-a217-efd338b8ec92", "cosmoshub-4", "uatom");
        // 私钥生成公钥、地址
        byte[] privateKey = Hex.decode("2d3f950aec4ab81da54bde1e2ac6309deccbc6443bfc0a91da15dc12c3eb96dd");
        CosmosCredentials credentials = CosmosCredentials.create(privateKey);
        // 获取地址
        System.out.println("address:" + credentials.getAddress());
        SendInfo sendInfo = SendInfo.builder().toAddress("cosmos1wphzgyg3r53szqkpnzm532q0x3vdk2zncn2fv4").amountInAtom(new BigDecimal("0.012")).build();
//        sendList.add(SendInfo.builder().credentials(credentials).toAddress("cosmos1u3zluamfx5pvgha0dn73ah4pyu9ckv6scvdw72").amountInAtom(new BigDecimal("0.0001")).build());
//        // 生成、签名、广播交易
        TxOuterClass.Tx tx = cosmosRestApiClient.send("cosmos1f74nxgxpequqmpqemdfz5dhr2sf873ydptxhrg", sendInfo, 6L, "123456");
        tx = cosmosRestApiClient.sign(tx, privateKey);
        System.out.println(cosmosRestApiClient.broad(tx));
//
//        // 获取指定高度的交易
//        ServiceOuterClass.GetTxsEventResponse txsEventByHeight = cosmosRestApiClient.getTxsEventByHeight(6900000L, "");
    }
}