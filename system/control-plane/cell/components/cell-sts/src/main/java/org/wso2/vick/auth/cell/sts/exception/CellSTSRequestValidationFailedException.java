package org.wso2.vick.auth.cell.sts.exception;

public class CellSTSRequestValidationFailedException extends Exception {

    public CellSTSRequestValidationFailedException(String message, Throwable e) {

        super(message, e);
    }

    public CellSTSRequestValidationFailedException(String message) {

        super(message);
    }
}
