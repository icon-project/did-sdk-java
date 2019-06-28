package foundation.icon.did;

import com.google.gson.JsonSyntaxException;
import foundation.icon.did.core.DidKeyHolder;
import foundation.icon.did.core.KeyProvider;
import foundation.icon.did.document.Converters;
import foundation.icon.did.document.Document;
import foundation.icon.did.document.EncodeType;
import foundation.icon.did.document.PublicKeyProperty;
import foundation.icon.did.exceptions.JwtException;
import foundation.icon.did.exceptions.ResolveException;
import foundation.icon.did.exceptions.TransactionException;
import foundation.icon.did.jwt.Jwt;
import foundation.icon.did.score.DidScore;
import foundation.icon.did.score.ScoreParameter;
import foundation.icon.icx.*;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.data.Bytes;
import foundation.icon.icx.data.TransactionResult;
import foundation.icon.icx.transport.jsonrpc.RpcError;
import foundation.icon.icx.transport.jsonrpc.RpcItem;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.*;

/**
 * This class use to enable the full functionality of DID Documents on a icon blockchain network.
 * <p>
 * In order to create and update DID Documents, a transaction is required and this class uses IconService.
 *
 * @see foundation.icon.icx.IconService
 * <a href ="https://github.com/icon-project/icon-sdk-java">icon-sdk-java</a>
 */
public class DidService {

    private IconService iconService;
    private DidScore didScore;
    private long readResultTimeout;

    /**
     * Create the instance.
     *
     * @param iconService  the IconService object
     * @param networkId    the network ID of the blockchain
     * @param scoreAddress the did score address deployed to the blockchain
     */
    public DidService(IconService iconService, BigInteger networkId, Address scoreAddress) {
        this(iconService, networkId, scoreAddress, 15_000);
    }

    /**
     * Create the instance.
     *
     * @param iconService  the IconService object
     * @param networkId    the network ID of the blockchain
     * @param scoreAddress the did score address deployed to the blockchain
     * @param timeout      the specified timeout, in milliseconds.
     */
    public DidService(IconService iconService, BigInteger networkId, Address scoreAddress, long timeout) {
        this.iconService = iconService;
        this.didScore = new DidScore(iconService, networkId, scoreAddress);
        this.readResultTimeout = timeout;
    }

    /**
     * Get the version of score.
     */
    public String getVersion() throws IOException {
        return didScore.getVersion();
    }

    /**
     * Create a DID Document.
     *
     * @param wallet    the wallet for transaction
     * @param publicKey the json string returned by calling
     *                  {@linkplain ScoreParameter#create(KeyProvider, EncodeType)}.
     * @return the Document object
     */
    public Document create(KeyWallet wallet, String publicKey) throws IOException {
        try {
            Converters.gson().fromJson(publicKey, PublicKeyProperty.class);
        } catch (ResolveException e) {
            throw new IllegalArgumentException("Publickey param is invalid.");
        }
        Transaction transaction = didScore.create(wallet.getAddress(), publicKey);
        Bytes hash = sendTransaction(transaction, wallet);
        TransactionResult result = getTransactionResult(hash);
        String did = getDid(result.getEventLogs(), "Create(Address,str,str)");
        return readDocument(did);
    }

    /**
     * Add a publicKey to DID Document.
     *
     * @param wallet    the wallet for transaction
     * @param signedJwt the string that signed the object returned by calling
     *                  {@linkplain ScoreParameter#addKey(DidKeyHolder, KeyProvider, EncodeType)}
     * @return the Document object
     */
    public Document addPublicKey(KeyWallet wallet, String signedJwt) throws IOException {
        TransactionResult result = sendJwt(wallet, signedJwt, "update");
        String did = getDid(result.getEventLogs(), "AddKey(Address,str,str)");
        return readDocument(did);
    }

    /**
     * Revoke a publicKey in the DID Document.
     *
     * @param wallet    the wallet for transaction
     * @param signedJwt the string that signed the object returned by calling
     *                  {@linkplain ScoreParameter#revokeKey(DidKeyHolder, String)}
     * @return the Document object
     */
    public Document revokeKey(KeyWallet wallet, String signedJwt) throws IOException {
        TransactionResult result = sendJwt(wallet, signedJwt, "update");
        String did = getDid(result.getEventLogs(), "RevokeKey(Address,str,str)");
        return readDocument(did);
    }

    /**
     * Get a DID Document.
     *
     * @param did the id of a DID Document
     * @return the Document object
     */
    public Document readDocument(String did) throws IOException {
        if (did == null) {
            throw new IllegalArgumentException("did cannot be null.");
        }
        String json = didScore.getDidDocument(did).asString();
        try {
            return Converters.gson().fromJson(json, Document.class);
        } catch (JsonSyntaxException e) {
            throw new ResolveException("'" + json + "' parsing error.");
        }
    }

    /**
     * Get a publicKey that matches the id of DID document and the id of publicKey.
     *
     * @param did   the id of DID document
     * @param keyId the id of publicKey
     * @return the publicKey object
     */
    public PublicKey getPublicKey(String did, String keyId) throws IOException {
        Document doc = readDocument(did);
        PublicKeyProperty publicKeyProperty = doc.getPublicKeyProperty(keyId);
        return publicKeyProperty.getPublicKey();
    }

    public String getDid(Address address) throws IOException {
        return didScore.getDid(address).asString();
    }

    /**
     * Get the id of document from the transaction event.
     *
     * @param eventLogs the EventLog object
     * @param eventName the name of score event
     * @return the id of document
     */
    protected String getDid(List<TransactionResult.EventLog> eventLogs, String eventName) {
        for (TransactionResult.EventLog log : eventLogs) {
            List<RpcItem> items = log.getIndexed();
            String func = items.get(0).asString();
            if (func.equals(eventName)) {
                return items.get(2).asString();
            }
        }
        return null;
    }


    /**
     * Sends a transaction with a json web token string.
     *
     * @param wallet    the wallet for transaction
     * @param signedJwt the string that signed the object returned from {@linkplain ScoreParameter}
     * @param method    the name of score function
     * @return the TransactionResult object
     */
    private TransactionResult sendJwt(KeyWallet wallet, String signedJwt, String method) throws IOException {
        try {
            if (Jwt.decode(signedJwt).getSignature() == null) {
                throw new IllegalArgumentException("JWT string must contain signature to send a transaction.");
            }
        } catch (JwtException e) {
            throw new IllegalArgumentException(e.getMessage());
        }

        Transaction transaction = didScore.jwtMethod(wallet.getAddress(), signedJwt, method);
        Bytes hash = sendTransaction(transaction, wallet);
        return getTransactionResult(hash);
    }

    /**
     * Sends a transaction.
     *
     * @param transaction the Transaction object
     * @param wallet      the wallet for transaction
     * @return the hash of transaction
     * @see foundation.icon.icx.IconService#sendTransaction(foundation.icon.icx.SignedTransaction)
     */
    protected Bytes sendTransaction(Transaction transaction, Wallet wallet) throws TransactionException {
        SignedTransaction signedTransaction = new SignedTransaction(transaction, wallet);
        try {
            return iconService.sendTransaction(signedTransaction).execute();
        } catch (IOException e) {
            throw new TransactionException(e.getMessage());
        }
    }

    /**
     * Get the transaction result that matches the hash of transaction.
     * This method calls {@linkplain IconService#getTransactionResult(Bytes)} every 1 second until
     * the transaction is confirmed.
     *
     * @param hash transaction hash
     * @return TransactionResult object
     * @see foundation.icon.icx.IconService#getTransactionResult(foundation.icon.icx.data.Bytes)
     */
    protected TransactionResult getTransactionResult(Bytes hash) throws IOException {

        try {
            final ExecutorService executor = Executors.newCachedThreadPool();
            return executor.submit(() -> {
                TransactionResult result = null;
                while (result == null) {
                    try {
                        Thread.sleep(1000);
                        result = iconService.getTransactionResult(hash).execute();
                        if (result.getStatus().equals(BigInteger.ZERO)) {
                            throw new TransactionException(result);
                        }
                    } catch (RpcError e) {
                        // pending
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return result;
            }).get(readResultTimeout, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            throw new TransactionException("timeout");
        } catch (Exception e) {
            throw new TransactionException(e.getMessage());
        }
    }

}

