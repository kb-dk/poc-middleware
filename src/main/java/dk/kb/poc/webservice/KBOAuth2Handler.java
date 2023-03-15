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
package dk.kb.poc.webservice;

import dk.kb.poc.config.ServiceConfig;
import dk.kb.util.webservice.exception.InternalServiceException;
import dk.kb.util.yaml.YAML;
import org.apache.commons.io.IOUtils;
import org.apache.cxf.interceptor.Fault;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.json.internal.json_simple.parser.JSONParser;
import org.jose4j.json.internal.json_simple.parser.ParseException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.ValidationException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Caching of public keys, validation of accessTokens etc. with a focus on the parts used at the Royal Danish Library.
 *
 * This class is thread safe.
 */
public class KBOAuth2Handler {
    private static final Logger log = LoggerFactory.getLogger(KBOAuth2Handler.class);

    public enum MODE {OFFLINE, ENABLED}

    private final MODE mode;
    private final String baseurl;
    private final Set<String > realms;
    private final int keysTTL;

    final Map<String, PublicKey> realmKeys;
    private static KBOAuth2Handler instance;

    /**
     * Fetches KB OAuth2 settings from the configuration and initializes the handler.
     *
     * If no OAUth2 configuration is present, a warning is logged and attempts to access OAuth-annotated endpoints
     * will fail, unless the role {@code public} is specified in the {@link KBAuthorization} annotation.
     */
    private KBOAuth2Handler() {
        YAML conf;
        if (!ServiceConfig.getConfig().containsKey(".config.security")) {
            log.warn("Authorization interceptor enabled, but there is no security setup in configuration at " +
                     "key .config.security");
            conf = new YAML();
        } else {
            conf = ServiceConfig.getConfig().getSubMap(".config.security");
        }

        mode = MODE.valueOf(conf.getString(".mode", MODE.ENABLED.toString()).toUpperCase(Locale.ROOT));
        if (mode == MODE.OFFLINE) {
            log.warn("Authorization mode is {}. Access tokens will not be properly checked. " +
                     "Set .config.security.mode to ENABLED to activate full access token validation", MODE.OFFLINE);
        }

        baseurl = trimTrailingSlash(conf.getString(".baseurl", null));
        if (baseurl == null && mode != MODE.OFFLINE) {
            log.warn("OAuth-enabled endpoints will fail: " +
                     "No .config.security.baseurl defined and .config.security.mode=" + mode);
        }

        realms = new HashSet<>(conf.getList(".realms", Collections.emptyList()));
        if (realms.isEmpty() && mode != MODE.OFFLINE) {
            log.warn("OAuth-enabled endpoints will fail: " +
                     "No .config.security.realms defined and .config.security.mode=" + mode);
        }

        keysTTL = conf.getInteger(".public_keys.ttl_seconds", 600);

        realmKeys = new TimeMap<>(keysTTL);

        log.info("Created " + this);
    }

    /**
     * @return singleton instance of thic class, initialized from {@link ServiceConfig}.
     */
    public static synchronized KBOAuth2Handler getInstance() {
        if (instance == null) {
            instance = new KBOAuth2Handler();
        }
        return instance;
    }

    /**
     * @param accessToken a trusted (validated) access token.
     * @return the roles listed in the realm in the token. This might be the empty list.
     */
    public Set<String> getTokenRoles(AccessToken accessToken) {
        return accessToken.getRealmAccess() == null ?
                Collections.emptySet() :
                accessToken.getRealmAccess().getRoles();
    }

    /**
     * Checks that the roles stated in the accessToken conforms to the endpointRoles.
     * @param endpoint name of the endpoint. Used for exceptions and logging.
     * @param accessToken a trusted (validated) access token.
     * @param endpointRoles the roles for the endpoint.
     * @throws VerificationException if access is not to be granted.
     */
    public void validateRoles(String endpoint, AccessToken accessToken, Set<String> endpointRoles)
            throws VerificationException {
        if (endpointRoles.contains(KBAuthorization.PUBLIC)) {
            log.debug("Granting access to endpoint '{}' as endpoint roles included '{}'",
                                                 endpoint, KBAuthorization.PUBLIC);
            return;
        }

        Set<String> realmRoles = getTokenRoles(accessToken);
        log.debug("got roles {} from access token for endpoint {}", realmRoles, endpoint);
        if (endpointRoles.contains(KBAuthorization.ANY) && !realmRoles.isEmpty()) {
            log.debug("Granting access to endpoint '{}' as endpoint roles included '{}' and realm role count was {}",
                      endpoint, KBAuthorization.PUBLIC, realmRoles.size());
            return;
        }

        for (String realmRole: realmRoles) {
            if (endpointRoles.contains(realmRole)) {
                log.debug("Granting access to endpoint '{}' as realm role '{}' was present in endpoint roles",
                          endpoint, realmRole);
                return;
            }
        }
        throw new VerificationException(String.format(
                Locale.ROOT,"Unable to match a realm role from %s to the endpoint roles %s for endpoint '%s'",
                realmRoles, endpointRoles, endpoint));
    }

    /**
     * No authorization header. Either throw an exception or accept entry if the endpoint is marked as public.
     *
     * @param endpoint      name of the endpoint. Used for exceptions and logging.
     * @param endpointRoles the roles for the endpoint. If {@code public} is one of the roles or if there are
     *                      no roles, access is granted.
     * @param invalidToken  if true, the reason for no authorization was failed verification.
     * @param failedReason if invalidToken is true, the reason for invalidation is given here.
     */
    public void handleNoAuthorization(String endpoint, Set<String> endpointRoles, boolean invalidToken, String failedReason) {
        switch (mode) {
            case OFFLINE:
                log.debug("Authorization skipped for endpoint '{}' as service security mode={}", endpoint, mode);
                break;
            case ENABLED:
                if (endpointRoles.contains(KBAuthorization.PUBLIC)) {
                    if (invalidToken) {
                        log.debug("Failed verification of provided access token (reason={}) but access to " +
                                  "endpoint '{}' granted as roles included '{}'",
                                  failedReason, endpoint, KBAuthorization.PUBLIC);
                    } else {
                        log.debug("No Authorization defined in request but access to endpoint '{}' granted as roles " +
                                  "included '{}'", endpoint, KBAuthorization.PUBLIC);
                    }
                    break;
                }
                if (endpointRoles.contains(KBAuthorization.ANY)) {
                    if (invalidToken) {
                        throw new Fault(new ValidationException(
                                "Failed verification of provided access token (reason=" + failedReason +
                                ") and endpoint " + endpoint + " requires a valid access token to be present"));
                    }
                    throw new Fault(new ValidationException(
                            "Authorization failed as there were no Authorization defined in request and " +
                            "endpoint " + endpoint + " requires it to be present"));
                }
                if (invalidToken) {
                    throw new Fault(new ValidationException(
                            "Failed verification of provided access token (reason=" + failedReason +
                            ") and endpoint " + endpoint + " requires a valid access token to be present with " +
                            "one of the roles " + endpointRoles));
                }
                throw new Fault(new ValidationException(
                        "Authorization failed as there were no Authorization defined in request and " +
                        "endpoint " + endpoint + " requires it to be present with one of the roles " + endpointRoles));
            default: {
                log.error("Unknown authorization mode: " + mode);
                throw new Fault(new InternalServiceException("Unknown authorization mode" + mode));
            }
        }
    }

    /**
     * Validate that the accessTokenString has allowed baseurl and realm, that is is not expired etc.
     * This does not check if the roles for the caller matches the roles for the endpoint.
     * @param encodedAccessToken untrusted Base64-encoded JSON, in multiple parts split by {@code .}.
     * @return a trusted (validated) AccessToken.
     * @throws VerificationException if the authorization validation failed.
     */
    public AccessToken validateAuthorization(String encodedAccessToken) throws VerificationException {
        return validateAuthorization(encodedAccessToken, mode);
    }

    /**
     * Validate that the accessTokenString has allowed baseurl and realm, that is is not expired etc.
     * This does not check if the roles for the caller matches the roles for the endpoint.
     * @param encodedAccessToken untrusted Base64-encoded JSON, in multiple parts split by {@code .}.
     * @param mode override of the configured mode.
     * @return a trusted (validated) AccessToken.
     * @throws VerificationException if the authorization validation failed.
     */
    AccessToken validateAuthorization(String encodedAccessToken, MODE mode) throws VerificationException {
        AccessToken trusted = checkTokenSignature(encodedAccessToken, mode);
        if (mode != MODE.OFFLINE) {
            checkToken(trusted);
        }
        return trusted;
    }

    /**
     * Parse the access token from the given string and validate its signature.
     * @param encodedAccessToken untrusted Base64-encoded JSON, in multiple parts split by {@code .}.
     * @param mode override of the configured mode.
     * @return a trusted (validated) AccessToken.
     * @throws VerificationException if the authorization validation failed.
     */
    AccessToken checkTokenSignature(String encodedAccessToken, MODE mode) throws VerificationException {
        String[] tokenParts = encodedAccessToken.split("[.]");
        if (tokenParts.length < 2) {
            log.warn("Received encodedAccessToken string without a dot: '{}'", encodedAccessToken);
            throw new VerificationException("Unsupported access token (no dot)");
        }

        JSONObject header = decodeJSONObject(tokenParts[0]);
        JSONObject payload = decodeJSONObject(tokenParts[1]);

        log.info("HACK_header\n" + header.toJSONString());
        log.info("HACK_payload\n" + payload.toJSONString());

        if (!header.containsKey("kid")) {
            throw new VerificationException("No key ID (kid) present in access token header");
        }
        if (!payload.containsKey("iss")) {
            throw new VerificationException("No issuer (iss) present in access token payload");
        }
        if (mode == MODE.OFFLINE) {
            log.debug("Authorization mode is " + MODE.OFFLINE + ": Skipping realmURL, publicKey and expiration checks");

            try {
                JWSInput jws = new JWSInput(encodedAccessToken);
                return jws.readJsonContent(AccessToken.class);
            } catch (JWSInputException e) {
                throw new VerificationException("Failed to parse JWT", e);
            }
        }

        String kid = header.get("kid").toString();
        String realm = getRealm(payload);
        //  "https://keycloak-keycloak.example.org/auth/realms/brugerbasen"
        String issuer = baseurl + "/" + realm;

        return TokenVerifier.create(encodedAccessToken, AccessToken.class)
                // TODO: Figure out why we can't trust iss
                //.withChecks(new TokenVerifier.RealmUrlCheck(issuer)) // String match only
                .publicKey(getRealmKey(realm, kid))
                .verify()
                .getToken();
    }


    /**
     * Validate issued date, expiry etc. for the given AccessToken.
     * @param trusted an AccessToken which has passed the cryptographic validation.
     * @throws VerificationException if any of the validation steps failed.
     */
    private void checkToken(AccessToken trusted) throws VerificationException {
        final long now = new Date().getTime();

        // Note: Timestamps in token is in seconds since Epoch. Date().getTime is milliseconds

        if (trusted.isExpired()) {
            long overtime = now/1000 - trusted.getExpiration();
            throw new VerificationException("AccessToken expired (" + overtime + " seconds too old)");
        }

        if (!trusted.isNotBefore(0)) {
            long missing = trusted.getNotBefore() - now/1000;
            throw new VerificationException("AccessToken not valid before " + missing + " seconds has passed");
        }

        if (trusted.getIssuedAt() > now) {
            long missing = trusted.getIssuedAt()/1000 - now;
            log.warn("Received trusted AccessToken issued {}} seconds in the future (epoch seconds = {})",
                     missing, trusted.getIssuedAt());
            throw new VerificationException("AccessToken issued " + missing + " seconds in the future");
        }

        if (!trusted.isActive()) {
            throw new VerificationException("AccessToken not active, cause not specified");
        }
    }

    /**
     * Extracts the realm from the issuer (iss) and verifies that it is on the list of accepted realms.
     * @param payload from an access token.
     * @return the realm, if present and accepted.
     * @throws VerificationException if the realm cannot be verified.
     */
    private String getRealm(JSONObject payload) throws VerificationException {
        String issuer = payload.get("iss").toString();
        Matcher issuerMatcher = ISSUER.matcher(issuer);
        if (!issuerMatcher.matches()) {
            String error = "Unable to determine realm from token payload iss '" + issuer + "'";
            log.warn(error);
            throw new VerificationException(error);
        }

        String tokenRealm = issuerMatcher.group(2);
        if (!realms.contains(tokenRealm)) {
            String error = String.format(
                    Locale.ROOT, "The provided realm '%s' from iss '%s' was not on the list of allowed realms",
                    tokenRealm, issuer);
            log.warn(error + " " + realms);
            throw new VerificationException(error);
        }
        return tokenRealm;
    }
    private static final Pattern ISSUER = Pattern.compile("^(.*)/(.+)/?$");

    private JSONObject decodeJSONObject(String base64JSON) throws VerificationException {
        String jsonString = new String(base64Decode(base64JSON), StandardCharsets.UTF_8);
        JSONParser parser = new JSONParser();
        // TODO: Switch to org.json
        try {
            return (JSONObject) parser.parse(jsonString);
        } catch (ParseException e) {
            log.warn("Unable to parse JSON in access token '{}'", jsonString);
            throw new VerificationException("Unable to parse JSON in access token");
        }
    }

    // The Base64 strings that come from a JWKS need some manipulation before they can be decoded.
     // we do that here
     private static byte[] base64Decode(String base64) {
         base64 = base64.replaceAll("-", "+");
         base64 = base64.replaceAll("_", "/");
         switch (base64.length() % 4) // Pad with trailing '='s
         {
             case 0:
                 break; // No pad chars in this case
             case 2:
                 base64 += "==";
                 break; // Two pad chars
             case 3:
                 base64 += "=";
                 break; // One pad char
             default:
                 throw new RuntimeException("Illegal base64url string '" + base64 + "'");
         }
         return Base64.getDecoder().decode(base64);
     }

    /**
     * Retrieved the key with the given kid from the given realm. Keys are cached, with Time to Live specified in
     * the configuration.
     * @param realm a Keycloak realm under the configured {@link #baseurl}.
     * @param kid the ID of the key to use for the realm.
     * @return the public key for the kid.
     */
     public PublicKey getRealmKey(String realm, String kid) throws VerificationException {
         final String cacheKey = realm + ":" + kid;
         PublicKey publicKey = realmKeys.get(cacheKey);
         if (publicKey != null) {
             return publicKey;
         }

         log.info("Retrieving public key for kid='{}' in realm '{}'", kid, realm);
         URL publicKeyURL = null;
         try {
             // https://keycloak-keycloak.apps.someopenshiftserver.example.org/auth/realms/brugerbasen/protocol/openid-connect/certs
             publicKeyURL = new URL(baseurl + "/" + realm + "/protocol/openid-connect/certs");
             log.debug("getRealmKey: Reading content of '{}'", publicKeyURL);
             String publicKeysString = IOUtils.toString(publicKeyURL, StandardCharsets.UTF_8);
             publicKey = extractPublicKey(kid, publicKeysString);
             realmKeys.put(cacheKey, publicKey);
         } catch (IOException e) {
             log.warn("Could not get public key for kid " + kid + " in realm " + realm + " from " + publicKeyURL, e);
             throw new VerificationException("Could not get public key for kid " + kid + " in realm " + realm, e);
         }
         return publicKey;
     }

    // Created by Jarl from Miracle

    /**
     * Given a public key JSON representation from a Keycloak server, parse the JSON and construct a PublicKey for the
     * stated kid (Key ID).
     * @param kid ID for the key to use.
     * @param publicKeysString JSON with public keys for the backing Keycloak server.
     * @return a PublicKey ready for use when verifying accessTokens.
     * @throws VerificationException if the public key could not be extracted, parsed or generated.
     */
    PublicKey extractPublicKey(String kid, String publicKeysString) throws VerificationException {
        String modulusStr = null;
        String exponentStr = null;
        try {
            JSONParser parser = new JSONParser();
            JSONObject json = (JSONObject) parser.parse(publicKeysString);
            // extract the kid value from the header
            JSONArray keylist = (JSONArray) json.get("keys");
            for (Object keyObject : keylist) {
                JSONObject key = (JSONObject) keyObject;
                String id = (String) key.get("kid");
                if (kid.equals(id)) {
                    modulusStr = (String) key.get("n");
                    exponentStr = (String) key.get("e");
                }
            }
        } catch (Exception e) {
            throw new VerificationException("Exception locating kid in accessToken", e);
        }

        if (modulusStr == null || exponentStr == null) {
            throw new VerificationException("kid was either not found or lacked n or e");
        }

        try  {
            BigInteger modulus = new BigInteger(1, base64Decode(modulusStr));
            BigInteger publicExponent = new BigInteger(1, base64Decode(exponentStr));

            // TODO: This should probably not be hardcoded. Fetch from keycloak instead
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (Exception e) {
            log.warn("Exception generating publicKey for kid='{}', modulus='{}', exponent='{}'",
                     kid, modulusStr, exponentStr);
            throw new VerificationException("Exception generating PublicKey for kid '" + kid + "'", e);
        }
    }

    /**
     * Remove trailing slash ({@code /)} from the given String. At most 1 slash is removed.
     * @param s input string.
     * @return the string without trailing slash.
     */
    public static String trimTrailingSlash(String s) {
        return s == null || !s.endsWith("/") ? s : s.substring(0, s.length()-1);
    }



    public MODE getMode() {
        return mode;
    }

    public String getBaseurl() {
        return baseurl;
    }

    public Set<String> getRealms() {
        return realms;
    }

    public int getKeysTTL() {
        return keysTTL;
    }

    public Map<String, PublicKey> getRealmKeys() {
        return realmKeys;
    }

    @Override
    public String toString() {
        return String.format(
                Locale.ROOT, "KBOAuth2Handler(mode=%s, baseurl='%s', realms=%s, keysTTL=%ss, cached realm keys=%d)",
                mode, baseurl, realms, keysTTL, realmKeys.size());
    }

}
