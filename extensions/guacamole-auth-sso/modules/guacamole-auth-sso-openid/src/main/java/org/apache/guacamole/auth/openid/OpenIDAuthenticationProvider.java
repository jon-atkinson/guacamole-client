/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.guacamole.auth.openid;

import java.util.Arrays;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.openid.conf.ConfigurationService;
import org.apache.guacamole.auth.sso.SSOAuthenticationProvider;
import org.apache.guacamole.auth.sso.SSOResource;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.RedirectField;
import org.apache.guacamole.language.TranslatableMessage;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;

/**
 * Guacamole authentication backend which authenticates users using an
 * arbitrary external system implementing OpenID. No storage for connections is
 * provided - only authentication. Storage must be provided by some other
 * extension.
 */
public class OpenIDAuthenticationProvider extends SSOAuthenticationProvider {

    /**
     * Creates a new OpenIDAuthenticationProvider that authenticates users
     * against an OpenID service.
     */
    public OpenIDAuthenticationProvider() {
        super(AuthenticationProviderService.class, SSOResource.class,
                new OpenIDAuthenticationProviderModule());
    }

    @Override
    public String getIdentifier() {
        return "openid";
    }

    @Override
    public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser,
            Credentials credentials) throws GuacamoleException {

        // Only handle users authenticated by this provider
        if (authenticatedUser.getAuthenticationProvider() != this)
            return authenticatedUser;

        // If a front-channel logout notification has been received for this
        // user, invalidate their session and redirect to the post-logout URI.
        // Using GuacamoleInvalidCredentialsException with a RedirectField
        // causes the frontend to perform a full page navigation, which also
        // closes any active WebSocket tunnels.
        FrontChannelLogoutService logoutService =
                getInjector().getInstance(FrontChannelLogoutService.class);
        if (logoutService.isLoggedOut(authenticatedUser.getIdentifier())) {
            ConfigurationService confService =
                    getInjector().getInstance(ConfigurationService.class);
            throw new GuacamoleInvalidCredentialsException(
                "Session invalidated by front-channel logout.",
                new CredentialsInfo(Arrays.asList(new Field[] {
                    new RedirectField("post_logout_redirect",
                            confService.getPostLogoutRedirectURI(),
                            new TranslatableMessage("LOGIN.INFO_IDP_REDIRECT_PENDING"))
                }))
            );
        }

        return authenticatedUser;

    }

}
