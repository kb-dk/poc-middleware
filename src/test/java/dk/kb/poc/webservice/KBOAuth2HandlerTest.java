package dk.kb.poc.webservice;

import dk.kb.poc.config.ServiceConfig;
import dk.kb.util.Resolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/**
 * This test class uses hardcoded public keys, access tokens etc. It does not require a running and/or mocked OAuth
 * server. This (unfortunately) also means that not all code paths are tested.
 */
class KBOAuth2HandlerTest {
    // Three parts devided by dots: header, payload and signature
    public static final String SAMPLE_ACCESS_TOKEN_1 =
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0cDVxMW53bnpKTEY5V2VMbEdFU2NzYXFaSDQtVGt6cFFwN0k0NTdY" +
            "WjhjIn0." +
            "eyJleHAiOjE2NDIzNzI0MzQsImlhdCI6MTY0MjM3MjEzNCwianRpIjoiMTAzZjI4NzMtYjMzNS00MzIzLWE0NjQtNWM1MDMzNzg3MjNm" +
            "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDg1L2F1dGgvcmVhbG1zL3Rlc3QtcmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoi" +
            "ZGEzODYxZWQtYzkwMS00YzlmLWI3NzItMWE2M2RiODMyOWVkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdC1jbGllbnQiLCJzZXNz" +
            "aW9uX3N0YXRlIjoiZDY0MGE0ODMtMzY4MS00ZDkwLTk4NGEtNDE4NmEzOTMyMjFkIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6" +
            "WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy10ZXN0LXJlYWxtIiwib2ZmbGluZV9hY2Nlc3MiLCJ1" +
            "bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJt" +
            "YW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6ImQ2NDBhNDgz" +
            "LTM2ODEtNGQ5MC05ODRhLTQxODZhMzkzMjIxZCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0" +
            "LXVzZXIifQ." +
            "G1u1YN3YG-9TTBtNFipEj9nCfCpftwHt6-WRu739Os1bq6QB1o5L7yB5BidQj-YgHzkrta8R0DzVJvQ6_bhDqsVtTapSvCfqJFQTCIoK" +
            "ALCGJc5nuMBYF24GMI0HyU-KRlCEZVWlqCH9lMjYo__YmDPUSSZ0WJhUJd0cHVO5b81-bGcr-rYBvAL77JZfgJ5X5IqmZXOEuXmyjrnG" +
            "2jXSld4z6JEAkdGiJg7tIwLAVWYPTprKUN_6yKlPIqjtQRO8QGbshPqL_occTkV2n4ogHznWfVc32U6OmV_TSGqYryf-WMX9nBugnoUL" +
            "Igi00U3usUloJ_P9XuCg9181SItc6w";

    public static final String SAMPLE_PUBLIC_KEY_1 =
            "{\n" +
            "    \"keys\": [\n" +
            "        {\n" +
            "            \"kid\": \"tp5q1nwnzJLF9WeLlGEScsaqZH4-TkzpQp7I457XZ8c\",\n" +
            "            \"kty\": \"RSA\",\n" +
            "            \"alg\": \"RS256\",\n" +
            "            \"use\": \"sig\",\n" +
            "            \"n\": \"qk6RFnWLZvuR7TnYkL5htIwO_P9xNPOGseKSiKCs0DMky4tAsjbEjqZHVDNSDeecXlIaNsRV3F0UaOagXWR" +
            "maaU9U5b1DrgOgTR1tRypW4wqEYnczW2etLUHKx_GqMbXoIiVZillMTl3JLFkWIumRBMJSSXLE3ROSzBlqydzTJifyIWJ26-E6FI9aO2" +
            "hpJHk7EuMs22EKwqGgsXB5ZUaEapqv7K2NNfPEquRviNa-igKwCZkANY54dI9E6asKjWWCLJWF_7ltfw08SotW3MugOd7si4MCM7NegY" +
            "JOipWq03Jj_6nQx-n78EL6F2IXzy_WBzbRpr39AmqROwiU4jEiQ\",\n" +
            "            \"e\": \"AQAB\",\n" +
            "            \"x5c\": [\n" +
            "                \"MIICozCCAYsCBgF+ZPDSVjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAp0ZXN0LXJlYWxtMB4XDTIyMDExNj" +
            "IyMDgzMVoXDTMyMDExNjIyMTAxMVowFTETMBEGA1UEAwwKdGVzdC1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK" +
            "pOkRZ1i2b7ke052JC+YbSMDvz/cTTzhrHikoigrNAzJMuLQLI2xI6mR1QzUg3nnF5SGjbEVdxdFGjmoF1kZmmlPVOW9Q64DoE0dbUcqV" +
            "uMKhGJ3M1tnrS1BysfxqjG16CIlWYpZTE5dySxZFiLpkQTCUklyxN0TkswZasnc0yYn8iFiduvhOhSPWjtoaSR5OxLjLNthCsKhoLFwe" +
            "WVGhGqar+ytjTXzxKrkb4jWvooCsAmZADWOeHSPROmrCo1lgiyVhf+5bX8NPEqLVtzLoDne7IuDAjOzXoGCToqVqtNyY/+p0Mfp+/BC+" +
            "hdiF88v1gc20aa9/QJqkTsIlOIxIkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAJFpPa66cuqt/0aYn1vFKm2Dlnp9Ys/EgX54B+/vsY2" +
            "/lqrSfMQUhQSAqtuZue+Hfew/NWjLBI0qK0AZstFn7yanw48FUx6+Wa+X7DyBO1wyluUg4iKV+MQ2GPy6/u9Xwd/Lovh7YvlEh4J6/SW" +
            "KfGOtZas2OaWc9IoBHm/f/CgkKdS9TvhQ+GB1bc95Sa/sUUWsptmV8G6HC+rAeeUrQp872cDoDd9dApDXQOCiyQMKXQCRpOSFRBI6GJp" +
            "Qapa+gwyUnDKYYX+RnabaNrXII2x3rVTlr0D7cDcbFGg6KZut71x1K4307bRWlHR4hxnPm3zfsyNJj7xsItIeUZmscLA==\"\n" +
            "            ],\n" +
            "            \"x5t\": \"jEvSSTBm7Z7Nc65It88wIkWm5PI\",\n" +
            "            \"x5t#S256\": \"o4D4kbhXaAQ-Uxof1OaozkBiwIsIu0gGWzhiPXUvFIE\"\n" +
            "        },\n" +
            "        {\n" +
            "            \"kid\": \"dB5cVVp-0nbTDtxi090tXQd45Y0SSg-UUXJJY3V3hMk\",\n" +
            "            \"kty\": \"RSA\",\n" +
            "            \"alg\": \"RSA-OAEP\",\n" +
            "            \"use\": \"enc\",\n" +
            "            \"n\": \"y41bWV2B59V1h8mzaQ7bpn5FxepkkDAW27VrX89yqlyMLuqyn_FKvDi_eACQEjtLktcFBQ6Foax5etS85Jz" +
            "PfmAdcdbS3YMaYd0HLMgiG00mclZdxm0F8yHUhW7JEdT2RU3mLfbJeVss8wNBcShOhAgJf1yKfspOEtFzRJaV8Azs47hUUD11E2eviIj" +
            "FCj-IhypzfZcoF2Amqt13HEfWRIDhclpvASyZpcV1OcQdhWm08mAcMaxi-KmUds0JxCytSaJKdUViN9IvN-ZRQwnP4UHgfOlF1JoA-Yf" +
            "kW_o1xggj6WTudRgEdDrPF6T56EnmWUnb6Rba0mgMdX-8Catezw\",\n" +
            "            \"e\": \"AQAB\",\n" +
            "            \"x5c\": [\n" +
            "                \"MIICozCCAYsCBgF+ZPDSgjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAp0ZXN0LXJlYWxtMB4XDTIyMDExNj" +
            "IyMDgzMVoXDTMyMDExNjIyMTAxMVowFTETMBEGA1UEAwwKdGVzdC1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM" +
            "uNW1ldgefVdYfJs2kO26Z+RcXqZJAwFtu1a1/PcqpcjC7qsp/xSrw4v3gAkBI7S5LXBQUOhaGseXrUvOScz35gHXHW0t2DGmHdByzIIh" +
            "tNJnJWXcZtBfMh1IVuyRHU9kVN5i32yXlbLPMDQXEoToQICX9cin7KThLRc0SWlfAM7OO4VFA9dRNnr4iIxQo/iIcqc32XKBdgJqrddx" +
            "xH1kSA4XJabwEsmaXFdTnEHYVptPJgHDGsYviplHbNCcQsrUmiSnVFYjfSLzfmUUMJz+FB4HzpRdSaAPmH5Fv6NcYII+lk7nUYBHQ6zx" +
            "ek+ehJ5llJ2+kW2tJoDHV/vAmrXs8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAEUat2mHhcPNRPkYvWOWQcZjAiYrwggZRNRDXcb1k7s" +
            "5q725XOLZVChxeRoViXf/U3/Y/Mq25tOdTGX8QN0Lb28upKLmM/BjT9V0JpnS+JFUWAmCLNoW2vNO09fvc7X5yRmKmdHC28plZfH6Pb9" +
            "S//0SrhgQ5fNkQlU2k6a5IlmtIrbDtZr7v4ubKD+g929ao7C/4qDDRYx6AGxmFNaZsjRdwiMFDvMYodL+teQyGQQkiVyGdyFj/ghKocV" +
            "bAJh2fw5MS13tJMucCjSCQF2Jx7cxiJgJEBJDRy6HJpRfhJBHyQm/yoddV9/GK0CdfQgRA1/bGMCFomzir+ommOqFXTA==\"\n" +
            "            ],\n" +
            "            \"x5t\": \"xD8YYUmJhMGs4usWgGNOYhRsNPY\",\n" +
            "            \"x5t#S256\": \"vYkTGwiVvDxezePxhuOQfeQ-DoS_4h_LUXvhWCrUoJw\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    public static final String SAMPLE_BASEURL_1 = "http://localhost:8085/auth/realms";
    public static final String SAMPLE_REALM_1 = "test-realm";
    public static final String SAMPLE_KID_1 = "tp5q1nwnzJLF9WeLlGEScsaqZH4-TkzpQp7I457XZ8c";

    @BeforeAll
    static void initConfig() throws IOException {
        Path knownFile = Path.of(Resolver.resolveURL("poc-middleware-test.yaml").getPath());
        ServiceConfig.initialize(knownFile.toString());
    }

    @Test
    void parsing() throws VerificationException {
        KBOAuth2Handler handler = KBOAuth2Handler.getInstance();
        // No real validation as the mode is OFFLINE, but the token is parsed.
        handler.validateAuthorization(SAMPLE_ACCESS_TOKEN_1, KBOAuth2Handler.MODE.OFFLINE);
    }

    @Test
    void tokenRoles() throws VerificationException {
        KBOAuth2Handler handler = KBOAuth2Handler.getInstance();
        AccessToken untrusted = handler.validateAuthorization(SAMPLE_ACCESS_TOKEN_1, KBOAuth2Handler.MODE.OFFLINE);
        Set<String> roles = handler.getTokenRoles(untrusted);
        assertTrue(roles.contains("default-roles-test-realm"), "There should be a role 'default-roles-test-realm'");
    }

    
    @Test
    void validateSignature() throws VerificationException {
        KBOAuth2Handler handler = KBOAuth2Handler.getInstance();

        injectPublicKey(handler);

        handler.checkTokenSignature(SAMPLE_ACCESS_TOKEN_1, KBOAuth2Handler.MODE.ENABLED);
    }

    @Test
    void validateNoContact() {
        KBOAuth2Handler handler = KBOAuth2Handler.getInstance();
        try {
            handler.validateAuthorization(SAMPLE_ACCESS_TOKEN_1);
            fail("Validation should fail as the OAuth2 server is not available");
        } catch (VerificationException e) {
            // Expected
        }
    }

    @Test
    void validateExpired() {
        KBOAuth2Handler handler = KBOAuth2Handler.getInstance();
        try {
            injectPublicKey(handler);
            handler.validateAuthorization(SAMPLE_ACCESS_TOKEN_1);
            fail("Validation should fail as the access token is expired");
        } catch (VerificationException e) {
            // Expected
        }
    }

    private void injectPublicKey(KBOAuth2Handler handler) throws VerificationException {
        // Inject the signature manually to avoid the handler trying to contact the server
        PublicKey publicKey = handler.extractPublicKey(SAMPLE_KID_1, SAMPLE_PUBLIC_KEY_1);
        handler.getRealmKeys().put(SAMPLE_REALM_1 + ":" + SAMPLE_KID_1, publicKey);
    }


}