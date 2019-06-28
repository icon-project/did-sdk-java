package foundation.icon.did.score;


import foundation.icon.icx.Call;
import foundation.icon.icx.IconService;
import foundation.icon.icx.Transaction;
import foundation.icon.icx.TransactionBuilder;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.transport.jsonrpc.RpcItem;
import foundation.icon.icx.transport.jsonrpc.RpcObject;
import foundation.icon.icx.transport.jsonrpc.RpcValue;

import java.io.IOException;
import java.math.BigInteger;

public class DidScore {

    private IconService iconService;
    private BigInteger networkId;
    private Address scoreAddress;

    public DidScore(IconService iconService, BigInteger networkId, Address scoreAddress) {
        this.iconService = iconService;
        this.networkId = networkId;
        this.scoreAddress = scoreAddress;
    }

    public Transaction jwtMethod(Address from, String jwt, String method) {
        RpcObject params = new RpcObject.Builder()
                .put("jwt", new RpcValue(jwt))
                .build();
        return buildTransaction(from, method, params);
    }

    public String getVersion() throws IOException {
        return iconService.call(buildCall(null, "getVersion", null, String.class)).execute();
    }

    public Transaction create(Address from, String publicKey) {
        RpcObject params = new RpcObject.Builder()
                .put("publicKey", new RpcValue(publicKey))
                .build();
        return buildTransaction(from, "create", params);
    }

    public RpcItem getDid(Address from) throws IOException {
        return iconService.call(buildCall(from, "getDid", null, RpcItem.class)).execute();
    }

    public RpcItem getDidDocument(String did) throws IOException {
        RpcObject params = new RpcObject.Builder()
                .put("did", new RpcValue(did))
                .build();
        return iconService.call(buildCall("read", params, RpcItem.class)).execute();
    }

    private Transaction buildTransaction(Address from, String method, RpcObject params) {
        long timestamp = System.currentTimeMillis() * 1000L;
        return TransactionBuilder.newBuilder()
                .nid(networkId)
                .from(from)
                .to(scoreAddress)
                .stepLimit(new BigInteger("2000000"))
                .timestamp(new BigInteger(Long.toString(timestamp)))
                .call(method)
                .params(params)
                .build();
    }

    private <T> Call<T> buildCall(String method, RpcObject params, Class<T> responseType) {
        return new Call.Builder()
                .to(scoreAddress)
                .method(method)
                .params(params)
                .buildWith(responseType);
    }

    private <T> Call<T> buildCall(Address from, String method, RpcObject params, Class<T> responseType) {
        return new Call.Builder()
                .from(from)
                .to(scoreAddress)
                .method(method)
                .params(params)
                .buildWith(responseType);
    }
}
