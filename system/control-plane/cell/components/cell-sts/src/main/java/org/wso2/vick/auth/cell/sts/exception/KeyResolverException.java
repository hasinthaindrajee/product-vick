package org.wso2.vick.auth.cell.sts.exception;

/**
 * Exception used to convey errors during key resolving.
 */
public class KeyResolverException extends Exception {

    public KeyResolverException(String errorMessage, Throwable throwable) {

        super(errorMessage, throwable);
    }

    public KeyResolverException(String errorMessage) {

        super(errorMessage);
    }

}
