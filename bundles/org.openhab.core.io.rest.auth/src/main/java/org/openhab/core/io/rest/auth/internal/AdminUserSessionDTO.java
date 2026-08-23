/*
 * Copyright (c) 2010-2026 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.core.io.rest.auth.internal;

import java.util.Date;

import org.eclipse.jdt.annotation.NonNullByDefault;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * A DTO representing a user session with the owning username attached.
 * Used for admin endpoints that list sessions across all users.
 *
 * @author Gabor Bicskei - Initial contribution
 */
@NonNullByDefault
@Schema(name = "AdminUserSession")
public class AdminUserSessionDTO {
    public String user;
    public String sessionId;
    public Date createdTime;
    public Date lastRefreshTime;
    public String clientId;
    public String scope;

    public AdminUserSessionDTO(String user, String sessionId, Date createdTime, Date lastRefreshTime, String clientId,
            String scope) {
        this.user = user;
        this.sessionId = sessionId;
        this.createdTime = createdTime;
        this.lastRefreshTime = lastRefreshTime;
        this.clientId = clientId;
        this.scope = scope;
    }
}
