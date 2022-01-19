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

import io.swagger.annotations.AuthorizationScope;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Mark a given method as requiring OAuth2 authorization with the given roles.
 *
 * The role "public" always means "access for all" and is not checked against user roles.
 * The role "any" means that any user role is accepted when verifying the access token:
 * It is up to the implementation to determine access based on user roles.
 *
 * Copied and slightly adjusted from the standard swagger Authorization.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface KBAuthorization {
    String PUBLIC = "public";
    String ANY = "any";

    String value();

    // AuthorizationScope is the standard Swagger annotation
    AuthorizationScope[] scopes() default {@AuthorizationScope(
            scope = "",
            description = ""
    )};
}
