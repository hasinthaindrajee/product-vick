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

package org.wso2.vick.auth.cell.jwks;

import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CarbonKeyResolver extends StaticKeyResolver {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X509Certificate certificate;

    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCW5kV1bXKeK3O2\n" +
            "RYsLrEp6BtFbGTL7k/SnhKFgQ6QezfRAjZUK5HpCjgHPmtOAsGuTLTdbUYBWtnG6\n" +
            "8pEaP1X34+aN0a1q7gJNe72kstyqeu5pzOhJ28FgDeVL1rvOAVTT6zqQyXYSEH6u\n" +
            "TuBeW4R6nuUg56fN+XZ/oihMprZ9WBV3dgqJIazIvi3O1LvS+aZfXbWqbSxMl0pY\n" +
            "/gfFfKor2d6iVcj19jIc5ggtU1nr3P/vc45WGSH+a9OZZkszsYzqwCmbItfo5dSn\n" +
            "zPSmRj69P/37NHHFCzsa6sLj8LWcresj/TJJSAYRp87Vq02NiaUU34ze1lfqcRwD\n" +
            "qD3ghq/JAgMBAAECggEAG07Iuxt3ZpBOfGnRY+dmAvdA48+HnmeEGtyxp44WIUz8\n" +
            "KsJ0emgmh+zS/xLxu5Qxo4zHO8tgAlE5+67x+2IC2L1xd7C+RV+VIxiFlUyZCnD8\n" +
            "vEDMuLEAKbXaDQNrMTikdUVYb+NFbrd1dW3oxKqjKt2ecXn6sBe5Dhf2WwjAdaY3\n" +
            "DiukJ9XDAlAaylmUsnaDBm4bH15u0QZBYJkDhrKsY1VvBgIjOqdeGMskASthW7g8\n" +
            "DPFW7x9Ris1VaJxAT2I7yLhMOsjzA/62D5AD4V/yNgoae3EtayjSY/CmY6AYS47t\n" +
            "yW9ZaI3QzoxztsuxkBeq+qXa9yHb/D2ey3cSFojiAQKBgQDmwLIBypakdsUPm5Su\n" +
            "QHm9DIwryOYKkJsdUTUpLlQqHGZJLTM15q531yHPALENyxdhkBfWULNoL87qK6kV\n" +
            "1gdm0Ac94rM3EprjzdXLJwdwoxyIT+t4vx/cXgZgXsdnE2p3g3yXfQHFokvd6BXi\n" +
            "820Czgebe4VRhkDi7dVvJGbZ2QKBgQCnaOolgc3ilnXbO7Qdi1m3fBCevlqIZ7GG\n" +
            "lyUUILzaampLY6tPsmhvPTErAf62sRlfwAegLlxM4sErnCePbVLgXR3VHncZ3cRg\n" +
            "sydaKcWXffEGg+vK6PJqouyfjpruyrn35JnBOLwp5GjuAjta+p03E/iLfBQWZ8ev\n" +
            "b1GFp/FfcQKBgQCzMDgLBBLvK/vjHuHaXt8qWzAOYDejRJ/vqDwr+noJKXyUnrEB\n" +
            "zlz1Wu46HUNgfrFtZcPc/VYUNevsFHN9LXMZ97ln6T9aKOx2skSvOWOhqEhj4gvs\n" +
            "/B31tl4lP/SAqqcmn8iEquJRYrKfY7Z7QqUIZI2rw8PHhwWkMyRm5lGoIQKBgFRr\n" +
            "4s/hQosGZw6UcAMKF8cgqFz1D0CEUhDWPZuF2tamHU5BR82b4XBfQmE201Ubv/j6\n" +
            "JJ5RYrhfDRzJ1WVNsyJzsqybfWIs5HADSE/+iqcXmqk3c3vStxSxbnQT/Ot4jgmF\n" +
            "XUgELVdO2N9VfsslYIy65HaqrpKR6S/+CfVFuMHxAoGAQam2OEe2bWsT9zSIdgNO\n" +
            "i9JH3+/uGNoVrlj3P3tiP73nIUUoi0tkIFwwwud6d2jCIh3L/MJ9anltkzLHRgZW\n" +
            "57joqUeLq7bseFYQGZaWG1MuMGW/H64GSFueEqMDSeEeEp53xEBjPn4KeaP4aDHB\n" +
            "NFhk6dCFu249FP7Sl8BnhoM=\n" +
            "-----END PRIVATE KEY-----";

    private static final String PUBLIC_KEY = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJV\n" +
            "UzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoT\n" +
            "BFdTTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3\n" +
            "MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN\n" +
            "TW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UEAxMJbG9jYWxob3N0\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWLC6xK\n" +
            "egbRWxky+5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V\n" +
            "9+PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXluE\n" +
            "ep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyq\n" +
            "K9neolXI9fYyHOYILVNZ69z/73OOVhkh/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+\n" +
            "vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYmlFN+M3tZX6nEcA6g94Iav\n" +
            "yQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUwDQYJKoZI\n" +
            "hvcNAQELBQADggEBABfk5mqsVUrpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8r\n" +
            "AJ06Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3EJ\n" +
            "CSfsvswtLVDZ7GDvTHKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdoz\n" +
            "qyOniVZd0QOxLAbcdt946chNdQvCm6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU\n" +
            "8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1qfyXM7xEotWoxmm6HZx8oWQ8\n" +
            "U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=\n" +
            "-----END CERTIFICATE-----";

    public CarbonKeyResolver() {

        try {
            privateKey = buildPrivateKey();
            certificate = (X509Certificate) buildCertificate(PUBLIC_KEY);
            publicKey = buildCertificate(PUBLIC_KEY).getPublicKey();
        } catch (KeyResolverException | CertificateException e) {
            e.printStackTrace();
        }
    }

    @Override
    public PrivateKey getPrivateKey() throws KeyResolverException {

        return privateKey;
    }

    private PrivateKey buildPrivateKey() throws KeyResolverException {

        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PRIVATE_KEY));
        String line;
        try {
            while ((line = rdr.readLine()) != null) {
                pkcs8Lines.append(line);
            }
        } catch (IOException e) {
            throw new KeyResolverException("Error while reading private key from given string", e);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

        // Base64 decode the result

        byte[] pkcs8EncodedBytes = new Base64().decode(pkcs8Pem);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        PrivateKey privKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privKey = kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyResolverException("Error while generating private key from given static string: ", e);
        }
        return privKey;
    }

    @Override
    public PublicKey getPublicKey() throws KeyResolverException {

        return publicKey;
    }

    @Override
    public X509Certificate getCertificate() throws KeyResolverException {

        return certificate;
    }

}
