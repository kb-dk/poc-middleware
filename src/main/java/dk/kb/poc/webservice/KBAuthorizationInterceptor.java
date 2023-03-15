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

import dk.kb.util.webservice.exception.InternalServiceException;
import io.swagger.annotations.AuthorizationScope;
import org.apache.cxf.helpers.CastUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.jaxrs.model.OperationResourceInfo;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.keycloak.common.VerificationException;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Intercepts webservices endpoints where the OpenAPI generated interface is annotated with {@link KBAuthorization}.
 *
 * The KBInterceptor expects that {@code config.security.baseurl} and {@code config.security.realms}
 * are defined in the setup. If not, all calls to endpoints annotated with {@link KBAuthorization} will fail.
 *
 * Example: {@code @KBAuthorization(roles={"student", "public"})}
 * "public" is a reserved role and means that all callers can send requests to the endpoint.
 * "student", while seemingly redundant because of "public" signals that a "student" role will give access with
 * escalated capabilities.
 * It is up to the implementation to determine what the response can be.
 *
 * NOTE: If present, authentication objects for {@link #ACCESS_TOKEN}, {@link #TOKEN_ROLES} and {@link #ENDPOINT_ROLES}
 * are added to the message when {@link #handleMessage(Message)} is called. These can be retrieved using e.g.
 * {@code JAXRSUtils.getCurrentMessage().get(KBAuthorizationInterceptor.TOKEN_ROLES)}.
 *
 * Note 2: If an endpoint is marked as {@link KBAuthorization#PUBLIC} but fails validation, {@link #VALID_TOKEN}
 * will be set to {@code false} and the reason for failed validation will be stated in {@link #FAILED_REASON}.
 */
public class KBAuthorizationInterceptor extends AbstractPhaseInterceptor<Message> {
    private static final Logger log = LoggerFactory.getLogger(KBAuthorizationInterceptor.class);
    private static final String AUTHORIZATION = "Authorization";
    private static final KBOAuth2Handler handler = KBOAuth2Handler.getInstance();

    /**
     * Key for storing a validated AccessToken parsed from the Message headers.
     */
    public static final String ACCESS_TOKEN = "AccessToken"; // AccessToken object
    /**
     * Key for storing the realm roles from the AccessToken.
     */
    public static final String TOKEN_ROLES = "TokenRoles"; // Set<String>
    /**
     * Key for storing the roles defined for the endpoint from the Message.
     */
    public static final String ENDPOINT_ROLES = "EndpointRoles"; // Set<String>

    /**
     * Whether or not the access token validates.
     * If the value is false, {@link #TOKEN_ROLES} will be empty and {@link #FAILED_REASON} will be present.
     */
    public static final String VALID_TOKEN = "ValidToken"; // Boolean

    /**
     * If {@link #VALID_TOKEN} is false, the reason for failed validation will be present here.
     */
    public static final String FAILED_REASON = "FailedReason"; // String

    public KBAuthorizationInterceptor() {
        super(Phase.PRE_INVOKE);
        KBOAuth2Handler.getInstance(); // Fail/log early
        log.info("Created " + this);
    }

    // Two interceptors: 1 token validator, 1 access control
    // message.getExchange().get(OperationResourceInfo.class)
    @Override
    public void handleMessage(Message message) throws Fault {
        final String endpoint = getEndpointName(message);
        log.debug("handleMessage({}) called", endpoint);

        if (getAnnotation(message) == null) {
            log.debug("Endpoint '{}' not annotated: No authorization required", endpoint);
            return;
        }

        Set<String> endpointRoles = getEndpointRoles(message);
        message.put(ENDPOINT_ROLES, endpoint);
        if (endpointRoles.isEmpty()) {
            if ("getResource".equals(endpoint)) {
                log.debug("No roles defined for endpoint '{}'. This is expected as it is a meta endpoint",
                          endpoint);
                return;
            } else {
                log.warn("No roles defined for endpoint '{}', even though it is annotated as requiring authentication",
                         endpoint);
            }
        }

        String accessTokenString = getAccessTokenString(message);
        if (accessTokenString == null) {
            handler.handleNoAuthorization(endpoint, endpointRoles, false, null);
            return;
        }

        // If authorization is defined we validate it, even if one of the endpoint roles is 'public'
        // TODO: Inject the Authorization token in the context of the call (put it in the Message)
        // TODO: Mark the Message as authenticated
        try {
            AccessToken accessToken = validateAuthorization(message);
            message.put(ACCESS_TOKEN, accessToken);
            message.put(TOKEN_ROLES, handler.getTokenRoles(accessToken));
            message.put(VALID_TOKEN, true);
            handler.validateRoles(endpoint, accessToken, endpointRoles);
        } catch (VerificationException e) {
            log.warn("VerificationException validating authorization for endpoint '" + endpoint + "'", e);
            message.put(VALID_TOKEN, false);
            message.put(FAILED_REASON, e.getMessage());
            handler.handleNoAuthorization(endpoint, endpointRoles, true, e.getMessage());
        } catch (Exception e) {
            log.warn("Non-VerificationException validating authorization for endpoint '" + endpoint + "'", e);
            message.put(VALID_TOKEN, false);
            message.put(FAILED_REASON, "Unknown");
            handler.handleNoAuthorization(endpoint, endpointRoles, true, null);
        }
    }

    /**
     * If defined, get the {@link KBAuthorization} from the endpoint stated in the message.
     * @param message CXF Message with the endpoint.
     * @return the authorization annotation for the endpoint or null if not annotated.
     */
    private KBAuthorization getAnnotation(Message message) {
        OperationResourceInfo ori = message.getExchange().get(OperationResourceInfo.class);
        if (ori == null) {
            return null;
        }
        Method method = ori.getAnnotatedMethod();
        if (method == null) {
            return null;
        }

        return method.getDeclaredAnnotation(KBAuthorization.class);
    }

    /**
     * Extract the OAuth roles from the endpoint requested in the message.
     * This does not use any Authorization defined by the caller.
     * @param message CXF message which defined endpoint and roles.
     * @return the roles defined for the endpoint or empty list if no roles are defined.
     */
    private Set<String> getEndpointRoles(Message message) {
        final String endpoint = getEndpointName(message);

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
            log.debug("No KBOAuth annotation for endpoint {} in OperationResourceInfo. " +
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

        return handler.validateAuthorization(parts[1]);
    }

    /**
     * Scans the {@link #AUTHORIZATION} headers for an entry with the pattern {@code "Bearer .*"} and returns the
     * part after {@code "Bearer "}, if present. This part should be a base64 representation of a JSON access token.
     * @param message CXF message with Authorization information.
     * @return a base64 representation of the JSON Bearer access token. Or null if not present.
     */
    private String getAccessTokenString(Message message) {
        Map<String, List<String>> headers = CastUtils.cast((Map<?, ?>)message.get(Message.PROTOCOL_HEADERS));
        if (headers == null) {
            throw new InternalServiceException("Unable to extract protocol headers");
        }

        List<String> authHeaders = headers.get(AUTHORIZATION);
        if (authHeaders == null) {
            return null;
        }

        String authorizationString = authHeaders.stream()
                .filter(value -> value.startsWith("Bearer "))
                .findFirst().orElse(null);
        if (authorizationString == null || authorizationString.isBlank()) {
            return null;
        }

        return authorizationString.split(" ", 2)[1];
    }


    public String toString() {
        return String.format(Locale.ROOT, "KBInterceptor(handler=%s)", handler);
    }

}
