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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.wso2.vick.auth.cell.sts.service.VickCellSTSException;

public class STSTokenGenerator {

    public static String generateToken(String incomingJWT, String audience, String issuer) throws VickCellSTSException {

        STSJWTBuilder stsjwtBuilder = new STSJWTBuilder();
        JWTClaimsSet jwtClaims = getJWTClaims(incomingJWT);
        stsjwtBuilder.subject(jwtClaims.getSubject());
        stsjwtBuilder.expiryInSeconds(3600);
        stsjwtBuilder.audience(audience);
        stsjwtBuilder.claims(jwtClaims.getClaims());
        stsjwtBuilder.issuer(issuer);
        return stsjwtBuilder.build();
    }

    public static String generateToken(String audience, String issuer) throws VickCellSTSException {

        STSJWTBuilder stsjwtBuilder = new STSJWTBuilder();
        stsjwtBuilder.expiryInSeconds(3600);
        stsjwtBuilder.audience(audience);
        stsjwtBuilder.issuer(issuer);
        return stsjwtBuilder.build();
    }

    public static JWTClaimsSet getJWTClaims(String jwt) throws VickCellSTSException {

        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new VickCellSTSException("Error while parsing the Signed JWT in authorization header.", e);
        }
    }
}
