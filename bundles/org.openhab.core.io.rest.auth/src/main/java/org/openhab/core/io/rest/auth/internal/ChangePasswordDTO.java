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

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * A DTO for changing a user's password.
 * <p>
 * The field is nullable since JSON deserialization may not provide the value.
 * Validation is performed in the resource method.
 *
 * @author Gabor Bicskei - Initial contribution
 */
@NonNullByDefault
@Schema(name = "ChangePassword")
public class ChangePasswordDTO {
    public @Nullable String newPassword;
}
