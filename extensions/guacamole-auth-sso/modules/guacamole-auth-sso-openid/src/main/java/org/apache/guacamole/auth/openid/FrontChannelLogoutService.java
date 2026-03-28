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

import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.openid.conf.ConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for tracking OpenID session IDs (sid claims) and managing
 * front-channel logout. At login, the sid from the user's ID token is
 * registered here. When a front-channel logout notification arrives from the
 * identity provider, the corresponding username is marked as pending logout.
 * On the user's next request, the OpenID authentication provider will detect
 * this and invalidate their Guacamole session.
 *
 * <p>State is intentionally in-memory only. In a multi-instance deployment,
 * front-channel logout notifications will only affect sessions on the instance
 * that receives them.
 */
@Singleton
public class FrontChannelLogoutService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(FrontChannelLogoutService.class);

    /**
     * Service for retrieving OpenID configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Maps OIDC session IDs (sid claims) to their associated Guacamole
     * usernames. Populated when a user successfully authenticates.
     */
    private final ConcurrentHashMap<String, String> sidToUsername = new ConcurrentHashMap<>();

    /**
     * Usernames whose sessions have been invalidated via front-channel logout
     * and have not yet been evicted. Entries are added by
     * {@link #invalidateBySid} and consumed (removed) by {@link #isLoggedOut}.
     */
    private final Set<String> pendingLogout =
            Collections.newSetFromMap(new ConcurrentHashMap<>());

    /**
     * Registers the association between an OIDC session ID and a Guacamole
     * username. Must be called whenever a user successfully authenticates via
     * OpenID and their ID token contains a sid claim.
     *
     * @param sid
     *     The OIDC session ID from the ID token's sid claim. If null or empty,
     *     the registration is silently skipped and front-channel logout will
     *     not be possible for this session.
     *
     * @param username
     *     The username of the authenticated user.
     */
    public void register(String sid, String username) {
        if (sid != null && !sid.isEmpty())
            sidToUsername.put(sid, username);
    }

    /**
     * Marks the Guacamole session associated with the given OIDC session ID
     * as pending logout, after validating that the issuer matches the
     * configured OpenID issuer. If no session is associated with the given
     * sid, this method has no effect.
     *
     * <p>If sid is null, a warning is logged per the OIDC Front-Channel
     * Logout spec — without a sid, individual session targeting is not
     * possible and no sessions are affected.
     *
     * @param iss
     *     The issuer from the front-channel logout request. Must match the
     *     value of openid-issuer in guacamole.properties.
     *
     * @param sid
     *     The OIDC session ID from the front-channel logout request, or null
     *     if the identity provider did not include one.
     *
     * @return
     *     True if a session was found and marked for logout, false otherwise.
     *
     * @throws GuacamoleException
     *     If configuration required for issuer validation cannot be read.
     */
    public boolean invalidateBySid(String iss, String sid) throws GuacamoleException {

        // Validate issuer if provided
        if (iss != null) {
            String configuredIssuer = confService.getIssuer();
            if (!configuredIssuer.equals(iss)) {
                logger.warn("Ignoring front-channel logout from unexpected issuer "
                        + "\"{}\". Expected \"{}\".", iss, configuredIssuer);
                return false;
            }
        }

        // Without a sid we cannot target a specific session
        if (sid == null || sid.isEmpty()) {
            logger.warn("Front-channel logout received without a sid parameter. "
                    + "Individual session invalidation requires sid. "
                    + "No sessions have been affected.");
            return false;
        }

        // Remove sid from registry and mark corresponding user for logout
        String username = sidToUsername.remove(sid);
        if (username == null) {
            logger.debug("Front-channel logout received for unknown sid \"{}\". "
                    + "Session may have already been invalidated or the sid "
                    + "was never registered (IdP may not include sid in ID "
                    + "tokens).", sid);
            return false;
        }

        pendingLogout.add(username);
        logger.info("Front-channel logout received for user \"{}\". "
                + "Session will be invalidated on next request.", username);
        return true;

    }

    /**
     * Returns whether the given user has a pending front-channel logout.
     * This method is destructive: the pending logout flag is cleared when
     * this returns true, so subsequent calls for the same username will
     * return false until another logout notification is received.
     *
     * @param username
     *     The username to check.
     *
     * @return
     *     True if the user has a pending front-channel logout, false otherwise.
     */
    public boolean isLoggedOut(String username) {
        return pendingLogout.remove(username);
    }

}
