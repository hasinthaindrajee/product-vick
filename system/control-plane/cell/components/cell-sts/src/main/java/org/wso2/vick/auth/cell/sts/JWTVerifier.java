/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.vick.auth.cell.sts;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.vick.auth.cell.CertificateUtils;
import org.wso2.vick.auth.cell.jwks.KeyResolverException;
import org.wso2.vick.auth.cell.sts.exception.JWTValidationFailedException;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class JWTVerifier {

    private Logger log = LoggerFactory.getLogger(JWTVerifier.class);

    private boolean validateSignature(SignedJWT signedJWT) throws JWTValidationFailedException {

        JWSVerifier verifier = null;
        JWSHeader header = signedJWT.getHeader();
        X509Certificate x509Certificate = null;
        try {
            x509Certificate = CertificateUtils.getKeyResolver().getCertificate();
        } catch (KeyResolverException e) {
            throw new JWTValidationFailedException("Error while retrieving certificate for JWT validation", e);
        }
        if (x509Certificate == null) {
            throw new JWTValidationFailedException("Unable to locate certificate");
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new JWTValidationFailedException("Algorithm must not be null.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.indexOf("RS") == 0) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new JWTValidationFailedException("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet : " + alg);
                }
            }
            if (verifier == null) {
                throw new JWTValidationFailedException("Could not create a signature verifier for algorithm type: " + alg);
            }
        }

        // At this point 'verifier' will never be null;
        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            throw new JWTValidationFailedException("Error verifying the JWT", e);
        }
    }
}
