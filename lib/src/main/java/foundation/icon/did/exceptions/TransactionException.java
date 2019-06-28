package foundation.icon.did.exceptions;

import foundation.icon.icx.data.TransactionResult;

public class TransactionException extends RuntimeException {
    private static String getMessage(TransactionResult result) {
        String message = "Fail transaction !! txHash:" + result.getTxHash();
        TransactionResult.Failure failure = result.getFailure();
        if (failure != null) {
            message = message + "\n" + failure.getMessage();
        }
        return message;
    }

    public TransactionException(String message) {
        super(message);
    }

    public TransactionException(TransactionResult result) {
        super(getMessage(result));
    }

}
