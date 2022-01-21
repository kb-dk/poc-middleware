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
import dk.kb.poc.webservice.exception.InternalServiceException;
import dk.kb.util.yaml.YAML;
import io.swagger.annotations.AuthorizationScope;
import org.apache.commons.io.IOUtils;
import org.apache.cxf.helpers.CastUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxrs.model.OperationResourceInfo;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.json.internal.json_simple.parser.JSONParser;
import org.jose4j.json.internal.json_simple.parser.ParseException;
import org.keycloak.TokenVerifier;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.keycloak.common.VerificationException;

import javax.xml.bind.ValidationException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Intercepts webservices endpoints where the OpenAPI generated interface is annotated with {@code @KBOAuth}.
 *
 * The KBInterceptor requires that {@code config.security.baseurl} and {@code config.security.realms}
 * are defined in the setup.
 *
 * Example: {@code @KBOAuth(roles={"student", "public"})}
 * "public" is a reserved role and means that all callers can send requests to the endpoint.
 * It if up to the implementation to determine what the response can be.
 */
// TODO: Throw proper HTTP Error codes-exceptions
public class KBAuthorizationInterceptor extends AbstractPhaseInterceptor<Message> {
    private static final Logger log = LoggerFactory.getLogger(KBAuthorizationInterceptor.class);
    private static final String AUTHORIZATION = "Authorization";

    public enum MODE {OFFLINE, ENABLED}

    private final MODE mode;
    private final String baseurl;
    private final Set<String > realms;
    private final int keysTTL;
    private final Map<String, PublicKey> realmKeys;

    public KBAuthorizationInterceptor() {
        super(Phase.PRE_INVOKE);
        KBOAuth2Handler.getInstance(); // Fail/log early
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

    // Two interceptors: 1 token validator, 1 access control
    // message.getExchange().get(OperationResourceInfo.class)
    @Override
    public void handleMessage(Message message) throws Fault {
        final String endpoint = message.getExchange().getEndpoint().getEndpointInfo().getName().getLocalPart();
        log.debug("handleMessage({}) called", endpoint);

        if (!isAnnotated(message)) {
            log.debug("Endpoint '{}' not annotated", endpoint);
            return;
        }

        Set<String> endpointRoles = getEndpointRoles(message);
        if (endpointRoles.isEmpty()) {
            log.warn("No roles defined for endpoint '{}', even though it is annotated as requiring authentication",
                     endpoint);
        }

        Map<String, List<String>> headers = CastUtils.cast((Map<?, ?>)message.get(Message.PROTOCOL_HEADERS));
        if (!headers.containsKey(AUTHORIZATION)) {
            handleNoAuthorization(endpoint, endpointRoles);
            return;
        }
        
        // If authorization is defined we validate it, even if one of the endpoint roles is 'public'
        // TODO: Inject the Authorization token in the context of the call (put it in the Message)
        // TODO: Mark the Message as authenticated
        try {
            AccessToken accessToken = validateAuthorization(message);
            validateRoles(endpoint, accessToken, endpointRoles);
        } catch (VerificationException e) {
            log.warn("VerificationException validating authorization", e);
            throw new Fault(e);
        } catch (Exception e) {
            log.warn("Non-VerificationException validating authorization", e);
            throw new Fault(e);
        }
    }

    private boolean isAnnotated(Message message) {
        OperationResourceInfo ori = message.getExchange().get(OperationResourceInfo.class);
        if (ori == null) {
            return false;
        }
        Method method = ori.getAnnotatedMethod();
        if (method == null) {
            return false;
        }

        return method.getDeclaredAnnotation(KBAuthorization.class) != null;
    }

    /**
     * Checks that the roles stated in the accessToken conforms to the endpointRoles.
     * @param endpoint name of the endpoint. Used for exceptions and logging.
     * @param accessToken   a trusted (validated) access token.
     * @param endpointRoles the roles for the endpoint.
     * @throws VerificationException if access is not to be granted.
     */
    private void validateRoles(String endpoint, AccessToken accessToken, Set<String> endpointRoles)
            throws VerificationException {
        if (endpointRoles.contains(KBAuthorization.PUBLIC)) {
            log.debug("Granting access to endpoint '{}' as endpoint roles included '{}'",
                      endpoint, KBAuthorization.PUBLIC);
            return;
        }

        Set<String> realmRoles = accessToken.getRealmAccess().getRoles();
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
     * @param endpoint name of the endpoint. Used for exceptions and logging.
     * @param endpointRoles the roles for the endpoint. If {@code public} is one of the roles, access is granted.
     */
    private void handleNoAuthorization(String endpoint, Set<String> endpointRoles) {
        switch (mode) {
            case OFFLINE:
                log.debug("Authorization skipped for endpoint '{}' as mode={}", endpoint, mode);
                break;
            case ENABLED:
                if (endpointRoles.contains(KBAuthorization.PUBLIC)) {
                    log.debug("No Authorization defined in request but endpoint '{}' roles included '{}'",
                              endpoint, KBAuthorization.PUBLIC);
                    break;
                }
                throw new Fault(new ValidationException(
                        "Authorization failed as there were no Authorization defined in request and endpoint " +
                        endpoint + " requires it to be present with roles " + endpointRoles));
            default: {
                log.error("Unknown authorization mode: " + mode);
                throw new Fault(new InternalServiceException("Unknown authorization mode" + mode));
            }
        }
    }

    /**
     * Extract the OAuth roles from the endpoint requested in the message.
     * This does not use any Authorization defined by the caller.
     * @param message CXF message which defined endpoint and roles.
     * @return the roles defined for the endpoint or empty list if no roles are defined.
     */
    private Set<String> getEndpointRoles(Message message) {
        final String endpoint = message.getExchange().getEndpoint().getEndpointInfo().getName().getLocalPart();

        OperationResourceInfo ori = message.getExchange().get(OperationResourceInfo.class);
        if (ori == null) {
            log.warn("No OperationResourceInfo for endpoint {}. Unable to determine required roles", endpoint);
            return Collections.emptySet();
        }

        Method method = ori.getAnnotatedMethod();
        if (method == null) {
            log.warn("No Annotated method in OperationResourceInfo for endpoint {}. " +
                     "Unable to determine required roles", endpoint);
            return Collections.emptySet();
        }

        KBAuthorization kbOAuth = method.getDeclaredAnnotation(KBAuthorization.class);
        if (kbOAuth == null) {
            log.warn("No KBOAuth annotation for endpoint {} in OperationResourceInfo. " +
                     "Unable to determine required roles", endpoint);
            return Collections.emptySet();
        }
        return Arrays.stream(kbOAuth.scopes())
                .map(AuthorizationScope::scope)
                .collect(Collectors.toSet());
    }

    /**
     * @return human readable name for the implementation class and method for the endpoint requested by the Message.
     */
    private String getEndpointName(Message message) {
        final String endpointClassName = message.getExchange().getEndpoint().getEndpointInfo().getName().getLocalPart();

        OperationResourceInfo ori = message.getExchange().get(OperationResourceInfo.class);
        if (ori == null) {
            log.warn("No OperationResourceInfo for endpoint {}. Unable to determine implementation method for the endpoint in the implementation class", endpointClassName);
            return endpointClassName;
        }

        Method method = ori.getAnnotatedMethod();
        if (method == null) {
            log.warn("No Annotated method in OperationResourceInfo for endpoint. " +
                     "Unable to determine endpoint implementation method name for implementation class {}",
                     endpointClassName);
            return endpointClassName;
        }
        return method.getName();
    }

    /**
     * Validate that the Authorization in the message has allowed baseurl and realm, that is is not expired etc.
     * This does not check if the roles for the caller matches the roles for the endpoint.
     * @param message CXF message with Authorization information.
     * @throws VerificationException if the authorization validation failed.
     * @return the validated AccessToken.
     */
    private AccessToken validateAuthorization(Message message) throws VerificationException {
        // TODO: Proper look after Bearer
        Map<String, List<String>> headers = CastUtils.cast((Map<?, ?>)message.get(Message.PROTOCOL_HEADERS));
        String authorizationString = headers.get(AUTHORIZATION).get(0);
        
        if (authorizationString == null || authorizationString.isBlank()) {
            throw new VerificationException("No authorization header in message");
        }

        String[] parts = authorizationString.split(" ");
        if (!"Bearer".equals(parts[0])) {
            throw new VerificationException(
                    "Expected the authorization header to start with 'Bearer ' " +
                    "but it started with '" + parts[0] + " '");
        }
        if (parts.length != 2) {
            log.warn("Received Authorization string without a space: '{}'", authorizationString);
            throw new VerificationException("Unsupported authorization String (no space)");
        }

        return validateAuthorization(parts[1]);
    }

    /**
     * Validate that the accessTokenString has allowed baseurl and realm, that is is not expired etc.
     * This does not check if the roles for the caller matches the roles for the endpoint.
     * @param encodedAccessToken Base64-encoded JSON, in multiple parts split by {@code .}.
     * @throws VerificationException if the authorization validation failed.
     * @return the validated AccessToken.
     */
    public AccessToken validateAuthorization(String encodedAccessToken) throws VerificationException {
        String[] tokenParts = encodedAccessToken.split("[.]");
        if (tokenParts.length < 2) {
            log.warn("Received encodedAccessToken string without a dot: '{}'", encodedAccessToken);
            throw new VerificationException("Unsupported access token (no dot)");
        }

        JSONObject header = decodeJSONObject(tokenParts[0]);
        JSONObject payload = decodeJSONObject(tokenParts[1]);

        if (!header.containsKey("kid")) {
            throw new VerificationException("No key ID (kid) present in access token header");
        }
        if (!payload.containsKey("iss")) {
            throw new VerificationException("No issuer (iss) present in access token payload");
        }
        String kid = header.get("kid").toString();
        String realm = validateAndGetRealm(payload);
        //  "https://keycloak-keycloak.example.org/auth/realms/brugerbasen"
        String issuer = baseurl + "/" + realm;

        // TODO: Switch from chained to step-by-step verification to get better error messages

        if (mode == MODE.OFFLINE) {
            log.info("Authorization mode is " + MODE.OFFLINE + ": Skipping realmURL, publicKey and expiration checks");
            return TokenVerifier.create(encodedAccessToken, AccessToken.class)
//                    .withChecks(new TokenVerifier.RealmUrlCheck(issuer)) // String match only
                    .verify()
                    .getToken();
        }
        // TODO: Figure out why there is a "Unchecked generics array creation" warning here and fix it
        return TokenVerifier.create(encodedAccessToken, AccessToken.class)
                .withChecks(new TokenVerifier.RealmUrlCheck(issuer)) // String match only
                .withChecks(new TokenVerifier.Predicate<AccessToken>() {
                    @Override
                    public boolean test(AccessToken accessToken) throws VerificationException {
                        return !accessToken.isExpired();
                    }
                })
                .publicKey(getRealmKey(realm, kid))
                // TODO: Check issuedAt is before now (sanity check / problemer med ur)
                .verify()
                .getToken();
    }

    /**
     * Extracts the realm from the issuer (iss) and verifies that it is on the list of accepted realms.
     * @param payload from an access token.
     * @return the realm, if present and accepted.
     * @throws VerificationException if the realm cannot be verified.
     */
    private String validateAndGetRealm(JSONObject payload) throws VerificationException {
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

    private static Pattern ISSUER = Pattern.compile("^(.*)/(.+)/?$");

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
     public byte[] base64Decode(String base64) {
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
                 throw new RuntimeException(
                         "Illegal base64url string!");
         }
         return Base64.getDecoder().decode(base64);
     }

    /**
     * Retrieved the key with the given kid from the given realm. Keys are cached, with Time to Live specified in
     * the configuration.
     * @param realm a Keycloak realm under the configured {@link #baseurl}.
     * @param kid the ID of the key to use for the realm.
     * @return the public key for the kid or null if it cannot be retrieved.
     */
     public PublicKey getRealmKey(String realm, String kid) throws VerificationException {
         final String cacheKey = realm + ":" + kid;
         PublicKey publicKey = realmKeys.get(cacheKey);
         if (publicKey != null) {
             return publicKey;
         }

         log.info("Retrieving public key for kid='{}' in realm '{}'", kid, realm);
         try {
         // https://keycloak-keycloak.apps.someopenshiftserver.example.org/auth/realms/brugerbasen/protocol/openid-connect/certs
             URL publicKeyURL = new URL(baseurl + "/" + realm + "/protocol/openid-connect/certs");
             log.debug("getRealmKey: Reading content of '{}'", publicKeyURL);
             String publicKeysString = IOUtils.toString(publicKeyURL, StandardCharsets.UTF_8);
             publicKey = extractPublicKey(kid, publicKeysString);
             realmKeys.put(cacheKey, publicKey);
         } catch (IOException e) {
             log.warn("Could not get public key for kid " + kid + " in realm " + realm, e);
             throw new VerificationException("Could not get public key for kid " + kid + " in realm " + realm, e);
         }
         return publicKey;
     }

    // TODO: Add caching
    public PublicKey getPublicKey(String kid) throws VerificationException {
        try {
            String publicKeysString = IOUtils.toString(new URL("https://keycloak-keycloak.apps.ocp-test.kb.dk/auth/realms/brugerbasen/protocol/openid-connect/certs"), StandardCharsets.UTF_8);
            return extractPublicKey(kid, publicKeysString);
        } catch (IOException e) {
            throw new RuntimeException("Could not get public key for kid" + kid);
        }
    }

    // TODO: Clean this up
    private PublicKey extractPublicKey(String kid, String response) throws VerificationException {
        try {
            String modulusStr = null;
            String exponentStr = null;
            JSONParser parser = new JSONParser();
            JSONObject json = (JSONObject) parser.parse(response);
            // extract the kid value from the header
            JSONArray keylist = (JSONArray) json.get("keys");
            for (Object keyObject : keylist) {
                JSONObject key = (JSONObject) keyObject;
                String id = (String) key.get("kid");
//                System.out.println("kid in response: " + id);
                if (kid.equals(id)) {
                    modulusStr = (String) key.get("n");
                    exponentStr = (String) key.get("e");
                }
            }

            if (modulusStr == null || exponentStr == null) {
                throw new VerificationException("kid was either not found or lacked n or e");
            }
            BigInteger modulus = new BigInteger(1, base64Decode(modulusStr));
            BigInteger publicExponent = new BigInteger(1, base64Decode(exponentStr));

            try {
                // TODO: This should probably not be hardcoded. Fetch from keycloak instead
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
            } catch (Exception e) {
                throw new VerificationException(e);
            }
        // TODO: Kill this abomination
        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new VerificationException("kid could not be extracted from the certs file");
    }

    private String trimTrailingSlash(String s) {
        return s == null || !s.endsWith("/") ? s : s.substring(0, s.length()-1);
    }

    public String toString() {
        return String.format(Locale.ROOT, "KBInterceptor(mode=%s, baseurl='%s', realms=%s, keysTTL=%ss)",
                             mode, baseurl, realms, keysTTL);
    }

}
