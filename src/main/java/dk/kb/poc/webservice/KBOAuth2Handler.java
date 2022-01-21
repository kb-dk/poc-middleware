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
import dk.kb.util.yaml.YAML;
import org.apache.cxf.phase.Phase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Caching of public keys, validation of accessTokens etc. with a focus on the parts used at the Royal Danish Library.
 */
public class KBOAuth2Handler {
    private static final Logger log = LoggerFactory.getLogger(KBOAuth2Handler.class);

    private final KBAuthorizationInterceptor.MODE mode;
    private final String baseurl;
    private final Set<String > realms;
    private final int keysTTL;

    private final Map<String, PublicKey> realmKeys;
    private static KBOAuth2Handler instance;

    /**
     * Fetches KB OAuth2 settings from the configuration and initializes the handler.
     *
     * If no OAUth2 configuration is present, a warning is logged and attempts to access OAuth-annotated endpoints
     * will fail, unless the role {@code public} is specified in the {@link #KBAuthorization} annotation.
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

        mode = KBAuthorizationInterceptor.MODE.valueOf(conf.getString(".mode", KBAuthorizationInterceptor.MODE.ENABLED.toString()).toUpperCase(Locale.ROOT));
        if (mode == KBAuthorizationInterceptor.MODE.OFFLINE) {
            log.warn("Authorization mode is {}. Access tokens will not be properly checked. " +
                     "Set .config.security.mode to ENABLED to activate full access token validation", KBAuthorizationInterceptor.MODE.OFFLINE);
        }

        baseurl = trimTrailingSlash(conf.getString(".baseurl", null));
        if (baseurl == null && mode != KBAuthorizationInterceptor.MODE.OFFLINE) {
            log.warn("OAuth-enabled endpoints will fail: " +
                     "No .config.security.baseurl defined and .config.security.mode=" + mode);
        }

        realms = new HashSet<>(conf.getList(".realms", Collections.emptyList()));
        if (realms.isEmpty() && mode != KBAuthorizationInterceptor.MODE.OFFLINE) {
            log.warn("OAuth-enabled endpoints will fail: " +
                     "No .config.security.realms defined and .config.security.mode=" + mode);
        }

        keysTTL = conf.getInteger(".public_keys.ttl_seconds", 600);

        realmKeys = new TimeMap<>(keysTTL);

        log.info("Created " + this);
    }

    public static KBOAuth2Handler getInstance() {
        if (instance == null) {
            instance = new KBOAuth2Handler();
        }
        return instance;
    }

    private String trimTrailingSlash(String s) {
        return s == null || !s.endsWith("/") ? s : s.substring(0, s.length()-1);
    }

    public String toString() {
        return String.format(
                Locale.ROOT, "KBOAuth2Handler(mode=%s, baseurl='%s', realms=%s, keysTTL=%ss, cached realm keys=%d)",
                mode, baseurl, realms, keysTTL, realmKeys.size());
    }

}
