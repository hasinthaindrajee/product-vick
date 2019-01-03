/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.vick.auth.cell.sts.service;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.vick.auth.cell.sts.CellStsUtils;
import org.wso2.vick.auth.cell.sts.STSTokenGenerator;
import org.wso2.vick.auth.cell.sts.context.store.UserContextStore;
import org.wso2.vick.auth.cell.sts.exception.TokenValidationFailureException;
import org.wso2.vick.auth.cell.sts.model.CellStsRequest;
import org.wso2.vick.auth.cell.sts.model.CellStsResponse;
import org.wso2.vick.auth.cell.sts.model.RequestDestination;
import org.wso2.vick.auth.cell.sts.model.config.CellStsConfiguration;
import org.wso2.vick.auth.cell.sts.validators.JWKSBasedJWTValidator;
import org.wso2.vick.auth.cell.sts.validators.JWTValidator;
import org.wso2.vick.sts.core.VickSTSConstants;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class VickCellStsService {

    private static final String VICK_AUTH_SUBJECT_HEADER = "x-vick-auth-subject";
    private static final String VICK_AUTH_SUBJECT_CLAIMS_HEADER = "x-vick-auth-subject-claims";
    private static final String AUTHORIZATION_HEADER_NAME = "authorization";
    private static final String BEARER_HEADER_VALUE_PREFIX = "Bearer ";
    private static final String STS_RESPONSE_TOKEN_PARAM = "token";

    private static final Logger log = LoggerFactory.getLogger(VickCellStsService.class);

    private UserContextStore userContextStore;
    private UserContextStore localContextStore;
    private CellStsConfiguration cellStsConfiguration;

    public VickCellStsService(CellStsConfiguration stsConfig,
                              UserContextStore contextStore, UserContextStore localContextStore) throws VickCellSTSException {

        this.userContextStore = contextStore;
        this.cellStsConfiguration = stsConfig;
        this.localContextStore = localContextStore;

        setHttpClientProperties();
    }

    public void handleInboundRequest(CellStsRequest cellStsRequest,
                                     CellStsResponse cellStsResponse) throws VickCellSTSException {

        // Extract the requestId
        String requestId = cellStsRequest.getRequestId();
        boolean isInterCellCall = false;

        String callerCell = cellStsRequest.getSource().getCellName();
        if (StringUtils.isNotEmpty(callerCell)) {
            isInterCellCall = true;
        }

        JWTClaimsSet jwtClaims;
        String jwt;
        JWT  incomingJWT;
        jwt = getUserContextJwt(cellStsRequest);
        try {
            incomingJWT = SignedJWT.parse(jwt);
        } catch (ParseException e) {
            return;
        }

        if (!isInterCellCall) {

            try {
                validateInboundToken(cellStsRequest, incomingJWT);
                userContextStore.put(requestId, jwt);
                jwtClaims = extractUserClaimsFromJwt(jwt);
            } catch (TokenValidationFailureException e) {
                e.printStackTrace();
            };

        } else {

            try {
                if (localContextStore.get(requestId) == null) {
                    validateInboundToken(cellStsRequest, incomingJWT);
                    localContextStore.put(requestId, jwt);
                    jwtClaims = extractUserClaimsFromJwt(jwt);
                } else {

                }

            } catch (TokenValidationFailureException e) {
                e.printStackTrace();
            };

        }
        if (userContextStore.containsKey(requestId)) {
            // User context is already available in the cell local context store. Load the user context from the store.
            log.debug("User context JWT found in context store. Loading user claims using context for requestId:{}",
                    requestId);
            jwtClaims = getUserClaimsFromContextStore(requestId);
            jwt = userContextStore.get(requestId);
        } else {
            // User context is not available in the cell local context store. This means we have intercepted a service
            // call from the Cell Gateway into a service. We need to extract the user claims from the JWT sent in
            // authorization header and store it in our user context store.
            log.debug("User context JWT not found in context store for requestId:{}. " +
                    "Extracting the user context JWT from the authorization header", requestId);
            jwt = getUserContextJwt(cellStsRequest);
            jwtClaims = extractUserClaimsFromJwt(jwt);

            // We store the JWT sent in the authorization header against the request Id
            userContextStore.put(requestId, jwt);
            log.debug("User context JWT added to context store for requestId:{}", requestId);
        }

        try {
            validateInboundToken(cellStsRequest, SignedJWT.parse(jwt));
        } catch (ParseException | TokenValidationFailureException e) {
            throw new VickCellSTSException("Error while validating JWT", e);
        }

        Map<String, String> headersToSet = new HashMap<>();
        headersToSet.put(VICK_AUTH_SUBJECT_HEADER, jwtClaims.getSubject());
        headersToSet.put(VICK_AUTH_SUBJECT_CLAIMS_HEADER, new PlainJWT(jwtClaims).serialize());

        cellStsResponse.addResponseHeaders(headersToSet);
    }

    private void validateInboundToken(CellStsRequest cellStsRequest, JWT jwt) throws TokenValidationFailureException {

        String jwkEndpoint = cellStsConfiguration.getGlobalJWKEndpoint();

        if (StringUtils.isNotEmpty(cellStsRequest.getSource().getCellName())) {
            jwkEndpoint = "http://" + cellStsRequest.getSource().getCellName() + "--sts-service:8085";
        }

        log.debug("Calling jwks endpoint: " + jwkEndpoint);
        JWTValidator jwtValidator = new JWKSBasedJWTValidator();
        jwtValidator.validateSignature(jwt, jwkEndpoint, "RS256", null);

    }

    private String getUserContextJwt(CellStsRequest cellStsRequest) {

        String authzHeaderValue = getAuthorizationHeaderValue(cellStsRequest);
        return extractJwtFromAuthzHeader(authzHeaderValue);
    }

    public void handleOutboundRequest(CellStsRequest cellStsRequest,
                                      CellStsResponse cellStsResponse) throws VickCellSTSException {

        // First we check whether the destination of the intercepted call is within VICK
        RequestDestination destination = cellStsRequest.getDestination();
        if (destination.isExternalToVick()) {
            // If the intercepted call is to an external workload to VICK we cannot do anything in the Cell STS.
            log.info("Intercepted an outbound call to a workload:{} outside VICK. Passing the call through.", destination);
        } else {
            log.info("Intercepted an outbound call to a workload:{} within VICK. Injecting a STS token for " +
                    "authentication and user-context sharing from Cell STS.", destination);

            String stsToken = getStsToken(cellStsRequest);
            if (StringUtils.isEmpty(stsToken)) {
                throw new VickCellSTSException("No JWT token received from the STS endpoint: "
                        + cellStsConfiguration.getStsEndpoint());
            }
            // Set the authorization header
            cellStsResponse.addResponseHeader(AUTHORIZATION_HEADER_NAME, BEARER_HEADER_VALUE_PREFIX + stsToken);
        }
    }

    private String getAuthorizationHeaderValue(CellStsRequest request) {

        return request.getRequestHeaders().get(AUTHORIZATION_HEADER_NAME);
    }

    private JWTClaimsSet extractUserClaimsFromJwt(String jwt) throws VickCellSTSException {

        if (StringUtils.isBlank(jwt)) {
            throw new VickCellSTSException("Cannot extract user context JWT from Authorization header.");
        }

        return getJWTClaims(jwt);
    }

    private JWTClaimsSet getUserClaimsFromContextStore(String requestId) throws VickCellSTSException {

        String jwt = userContextStore.get(requestId);
        return getJWTClaims(jwt);
    }

    private String extractJwtFromAuthzHeader(String authzHeader) {

        if (StringUtils.isBlank(authzHeader)) {
            return null;
        }

        String[] split = authzHeader.split("\\s+");
        return split.length > 1 ? split[1] : null;
    }

    private JWTClaimsSet getJWTClaims(String jwt) throws VickCellSTSException {

        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new VickCellSTSException("Error while parsing the Signed JWT in authorization header.", e);
        }
    }

    private String getStsToken(CellStsRequest request) throws VickCellSTSException {

        try {
            // Check for a stored user context
            String requestId = request.getRequestId();
            String stsEndpoint = cellStsConfiguration.getStsEndpoint();
            // This is the original JWT sent to the cell gateway.
            String jwt = userContextStore.get(requestId);

            // Check whether the outbound call is Inter Cell or Intra Cell
            if (isIntraCellCall(request)) {
                // We first try to reuse a JWT token cached within the cell.
                if (StringUtils.isBlank(jwt)) {
                    log.debug("No JWT was found in the user context store for requestId:{}. " +
                            "Calling the local STS endpoint to get a JWT for inter cell communication. " +
                            "Destination:{}.", requestId, request.getDestination());
                    return getTokenFromLocalSTS(CellStsUtils.getMyCellName());
                } else {
                    // We found a JWT cached in the user context store. We are going to reuse it.
                    log.debug("Found a valid JWT in user context store for requestId:{}. Reusing it.", requestId);
                    return getTokenFromLocalSTS(jwt, CellStsUtils.getMyCellName());
                }
            } else {
                // This is an inter cell call. So I need to get a token within the audience set to my destination cell.
                String destinationCell = request.getDestination().getCellName();
                log.debug("Requesting a JWT token from the global STS:{} to talk to inter cell communication. " +
                        "Destination:{}", stsEndpoint, request.getDestination());
                return getTokenFromLocalSTS(jwt, destinationCell);
            }

        } finally {
            // do nothing
        }
    }

    private boolean isIntraCellCall(CellStsRequest cellStsRequest) throws VickCellSTSException {

        String currentCell = CellStsUtils.getMyCellName();
        String destinationCell = cellStsRequest.getDestination().getCellName();

        return StringUtils.equals(currentCell, destinationCell);
    }

    private String getTokenFromGlobalSTS(String audience) throws UnirestException {

        return getTokenFromGlobalSTS(audience, null);
    }

    private String getTokenFromLocalSTS(String audience) throws VickCellSTSException {

        return STSTokenGenerator.generateToken(audience, null);
    }

    private String getTokenFromLocalSTS(String jwt, String audience) throws VickCellSTSException {

        String token = STSTokenGenerator.generateToken(jwt, audience, cellStsConfiguration.getCellName()
                + "--sts-service");
        return token;
    }

    private String getTokenFromGlobalSTS(String audience, String userContextJwt) throws UnirestException {

        String stsEndpointUrl = cellStsConfiguration.getStsEndpoint();
        String username = cellStsConfiguration.getUsername();
        String password = cellStsConfiguration.getPassword();
        String cellName = cellStsConfiguration.getCellName();

        HttpResponse<JsonNode> apiResponse =
                Unirest.post(stsEndpointUrl)
                        .basicAuth(username, password)
                        .field(VickSTSConstants.VickSTSRequest.SUBJECT, cellName)
                        .field(VickSTSConstants.VickSTSRequest.USER_CONTEXT_JWT, userContextJwt)
                        .field(VickSTSConstants.VickSTSRequest.AUDIENCE, audience)
                        .asJson();

        log.debug("Response from the STS:\nstatus:{}\nbody:{}",
                apiResponse.getStatus(), apiResponse.getBody().toString());

        if (apiResponse.getStatus() == 200) {
            Object stsTokenValue = apiResponse.getBody().getObject().get(STS_RESPONSE_TOKEN_PARAM);
            return stsTokenValue != null ? stsTokenValue.toString() : null;
        } else {
            log.error("Error from STS endpoint. statusCode= " + apiResponse.getStatus() + ", " +
                    "statusMessage=" + apiResponse.getStatusText());
            return null;
        }
    }

    private void setHttpClientProperties() throws VickCellSTSException {

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        };

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);


        try {

            // TODO add the correct certs for hostname verification..
            Unirest.setHttpClient(HttpClients.custom()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, (x509Certificates, s) -> true).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .disableRedirectHandling()
                    .build());
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            throw new VickCellSTSException("Error initializing the http client.", e);
        }
    }
}
