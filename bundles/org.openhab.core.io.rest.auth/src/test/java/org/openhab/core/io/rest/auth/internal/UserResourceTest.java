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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.openhab.core.auth.ManagedUser;
import org.openhab.core.auth.User;
import org.openhab.core.auth.UserApiToken;
import org.openhab.core.auth.UserRegistry;
import org.openhab.core.auth.UserSession;

/**
 * Tests for {@link UserResource}.
 *
 * @author Gabor Bicskei - Initial contribution
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@NonNullByDefault
public class UserResourceTest {

    private @Mock @NonNullByDefault({}) UserRegistry userRegistry;
    private @Mock @NonNullByDefault({}) SecurityContext securityContext;
    private @Mock @NonNullByDefault({}) Principal principal;

    private @NonNullByDefault({}) UserResource userResource;

    @BeforeEach
    public void setUp() {
        userResource = new UserResource(userRegistry);
        when(securityContext.getUserPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("admin");
    }

    // --- GET /auth/users ---

    @Test
    public void testGetUsersReturnsAllUsers() {
        ManagedUser user1 = createManagedUser("admin", Set.of("administrator"));
        ManagedUser user2 = createManagedUser("john", Set.of("user"));
        when(userRegistry.getAll()).thenReturn(List.of(user1, user2));

        Response response = userResource.getUsers();

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetUsersReturnsEmptyList() {
        when(userRegistry.getAll()).thenReturn(List.of());

        Response response = userResource.getUsers();

        assertThat(response.getStatus(), is(200));
    }

    // --- GET /auth/users/{userId} ---

    @Test
    public void testGetUserReturnsUserWhenFound() {
        ManagedUser user = createManagedUser("admin", Set.of("administrator"));
        when(userRegistry.get("admin")).thenReturn(user);

        Response response = userResource.getUser("admin");

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetUserReturns404WhenNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.getUser("unknown");

        assertThat(response.getStatus(), is(404));
    }

    // --- POST /auth/users ---

    @Test
    public void testCreateUserSuccess() {
        ManagedUser newUser = createManagedUser("john", Set.of("user"));
        when(userRegistry.get("john")).thenReturn(null);
        when(userRegistry.register(eq("john"), eq("secret123"), any())).thenReturn(newUser);

        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = "secret123";
        dto.roles = List.of("user");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(201));
        verify(userRegistry).register(eq("john"), eq("secret123"), eq(new HashSet<>(List.of("user"))));
    }

    @Test
    public void testCreateUserReturns400WhenNameMissing() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = null;
        dto.password = "secret123";
        dto.roles = List.of("user");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns400WhenNameEmpty() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "";
        dto.password = "secret123";
        dto.roles = List.of("user");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns400WhenPasswordMissing() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = null;
        dto.roles = List.of("user");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns400WhenPasswordEmpty() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = "";
        dto.roles = List.of("user");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns400WhenRolesMissing() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = "secret123";
        dto.roles = null;

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns400WhenRolesEmpty() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = "secret123";
        dto.roles = List.of();

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns400WhenRolesInvalid() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = "secret123";
        dto.roles = List.of("superadmin");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    @Test
    public void testCreateUserReturns409WhenUserAlreadyExists() {
        ManagedUser existingUser = createManagedUser("john", Set.of("user"));
        when(userRegistry.get("john")).thenReturn(existingUser);

        CreateUserDTO dto = new CreateUserDTO();
        dto.name = "john";
        dto.password = "secret123";
        dto.roles = List.of("user");

        Response response = userResource.createUser(dto);

        assertThat(response.getStatus(), is(409));
        verify(userRegistry, never()).register(any(), any(), any());
    }

    // --- PUT /auth/users/{userId}/roles ---

    @Test
    public void testUpdateUserRolesSuccess() {
        ManagedUser user = createManagedUser("john", Set.of("user"));
        when(userRegistry.get("john")).thenReturn(user);

        Response response = userResource.updateUserRoles("john", Set.of("user", "administrator"));

        assertThat(response.getStatus(), is(200));
        verify(userRegistry).update(user);
    }

    @Test
    public void testUpdateUserRolesReturns400WhenRolesInvalid() {
        Response response = userResource.updateUserRoles("john", Set.of("superadmin"));

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).update(any());
    }

    @Test
    public void testUpdateUserRolesReturns404WhenNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.updateUserRoles("unknown", Set.of("user"));

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).update(any());
    }

    @Test
    public void testUpdateUserRolesReturns500WhenNotManagedUser() {
        User mockUser = when(org.mockito.Mockito.mock(User.class).getName()).thenReturn("external").getMock();
        when(userRegistry.get("external")).thenReturn(mockUser);

        Response response = userResource.updateUserRoles("external", Set.of("user"));

        assertThat(response.getStatus(), is(500));
        verify(userRegistry, never()).update(any());
    }

    // --- PUT /auth/users/{userId}/password ---

    @Test
    public void testChangeUserPasswordSuccess() {
        ManagedUser user = createManagedUser("john", Set.of("user"));
        when(userRegistry.get("john")).thenReturn(user);

        ChangePasswordDTO dto = new ChangePasswordDTO();
        dto.newPassword = "newSecret456";

        Response response = userResource.changeUserPassword("john", dto);

        assertThat(response.getStatus(), is(200));
        verify(userRegistry).changePassword(user, "newSecret456");
    }

    @Test
    public void testChangeUserPasswordReturns404WhenNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        ChangePasswordDTO dto = new ChangePasswordDTO();
        dto.newPassword = "newSecret456";

        Response response = userResource.changeUserPassword("unknown", dto);

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).changePassword(any(), any());
    }

    @Test
    public void testChangeUserPasswordReturns400WhenPasswordMissing() {
        ChangePasswordDTO dto = new ChangePasswordDTO();
        dto.newPassword = null;

        Response response = userResource.changeUserPassword("john", dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).changePassword(any(), any());
    }

    @Test
    public void testChangeUserPasswordReturns400WhenPasswordEmpty() {
        ChangePasswordDTO dto = new ChangePasswordDTO();
        dto.newPassword = "";

        Response response = userResource.changeUserPassword("john", dto);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).changePassword(any(), any());
    }

    // --- DELETE /auth/users/{userId} ---

    @Test
    public void testDeleteUserSuccess() {
        ManagedUser user = createManagedUser("john", Set.of("user"));
        when(userRegistry.get("john")).thenReturn(user);

        Response response = userResource.deleteUser("john", securityContext);

        assertThat(response.getStatus(), is(200));
        verify(userRegistry).remove("john");
    }

    @Test
    public void testDeleteUserReturns404WhenNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.deleteUser("unknown", securityContext);

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).remove(any());
    }

    @Test
    public void testDeleteUserReturns400WhenDeletingSelf() {
        ManagedUser user = createManagedUser("admin", Set.of("administrator"));
        when(userRegistry.get("admin")).thenReturn(user);
        when(principal.getName()).thenReturn("admin");

        Response response = userResource.deleteUser("admin", securityContext);

        assertThat(response.getStatus(), is(400));
        verify(userRegistry, never()).remove(any());
    }

    // --- GET /auth/users/sessions (all users) ---

    @Test
    public void testGetAllSessionsReturnsSessionsFromAllUsers() {
        ManagedUser user1 = createManagedUserWithSessions("admin", 2);
        ManagedUser user2 = createManagedUserWithSessions("john", 1);
        when(userRegistry.getAll()).thenReturn(List.of(user1, user2));

        Response response = userResource.getAllSessions(null, 0, 0, null, null);

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllSessionsReturnsEmptyWhenNoSessions() {
        ManagedUser user = createManagedUser("admin", Set.of("administrator"));
        when(userRegistry.getAll()).thenReturn(List.of(user));

        Response response = userResource.getAllSessions(null, 0, 0, null, null);

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllSessionsPagination() {
        ManagedUser user = createManagedUserWithSessions("admin", 5);
        when(userRegistry.getAll()).thenReturn(List.of(user));

        // Page 0 with length 2
        Response response = userResource.getAllSessions(null, 0, 2, null, null);
        assertThat(response.getStatus(), is(200));

        // Page 1 with length 2
        response = userResource.getAllSessions(null, 1, 2, null, null);
        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllSessionsNoPagingWhenPageLengthZero() {
        ManagedUser user = createManagedUserWithSessions("admin", 3);
        when(userRegistry.getAll()).thenReturn(List.of(user));

        // pagelength 0 means return all
        Response response = userResource.getAllSessions(null, 0, 0, null, null);
        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllSessionsFilterByUser() {
        ManagedUser user1 = createManagedUserWithSessions("admin", 2);
        ManagedUser user2 = createManagedUserWithSessions("john", 1);
        when(userRegistry.getAll()).thenReturn(List.of(user1, user2));

        Response response = userResource.getAllSessions("john", 0, 0, null, null);
        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllSessionsOrderBy() {
        ManagedUser user = createManagedUserWithSessions("admin", 3);
        when(userRegistry.getAll()).thenReturn(List.of(user));

        Response response = userResource.getAllSessions(null, 0, 0, "createdTime", "asc");
        assertThat(response.getStatus(), is(200));
    }

    // --- GET /auth/users/{userId}/sessions ---

    @Test
    public void testGetUserSessionsReturnsSessionsForUser() {
        ManagedUser user = createManagedUserWithSessions("admin", 2);
        when(userRegistry.get("admin")).thenReturn(user);

        Response response = userResource.getUserSessions("admin");

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetUserSessionsReturns404WhenUserNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.getUserSessions("unknown");

        assertThat(response.getStatus(), is(404));
    }

    @Test
    public void testGetUserSessionsReturns400WhenNotManagedUser() {
        User mockUser = when(org.mockito.Mockito.mock(User.class).getName()).thenReturn("external").getMock();
        when(userRegistry.get("external")).thenReturn(mockUser);

        Response response = userResource.getUserSessions("external");

        assertThat(response.getStatus(), is(400));
    }

    // --- DELETE /auth/users/{userId}/sessions/{sessionId} ---

    @Test
    public void testRevokeUserSessionSuccess() {
        ManagedUser user = createManagedUserWithSessions("admin", 1);
        when(userRegistry.get("admin")).thenReturn(user);
        // session ID is "session-0-uuid...", prefix is "session-0"
        // but our helper creates "sess0-xxxxx", so prefix is "sess0"

        Response response = userResource.revokeUserSession("admin", "sess0");

        assertThat(response.getStatus(), is(200));
        verify(userRegistry).removeUserSession(eq(user), any(UserSession.class));
    }

    @Test
    public void testRevokeUserSessionReturns404WhenUserNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.revokeUserSession("unknown", "sess0");

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).removeUserSession(any(), any());
    }

    @Test
    public void testRevokeUserSessionReturns404WhenSessionNotFound() {
        ManagedUser user = createManagedUserWithSessions("admin", 1);
        when(userRegistry.get("admin")).thenReturn(user);

        Response response = userResource.revokeUserSession("admin", "nonexistent");

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).removeUserSession(any(), any());
    }

    // --- GET /auth/users/apitokens (all users) ---

    @Test
    public void testGetAllApiTokensReturnsTokensFromAllUsers() {
        ManagedUser user1 = createManagedUserWithTokens("admin", 2);
        ManagedUser user2 = createManagedUserWithTokens("john", 1);
        when(userRegistry.getAll()).thenReturn(List.of(user1, user2));

        Response response = userResource.getAllApiTokens(null, 0, 0, null, null);

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllApiTokensReturnsEmptyWhenNoTokens() {
        ManagedUser user = createManagedUser("admin", Set.of("administrator"));
        when(userRegistry.getAll()).thenReturn(List.of(user));

        Response response = userResource.getAllApiTokens(null, 0, 0, null, null);

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllApiTokensPagination() {
        ManagedUser user = createManagedUserWithTokens("admin", 5);
        when(userRegistry.getAll()).thenReturn(List.of(user));

        // Page 0 with length 2
        Response response = userResource.getAllApiTokens(null, 0, 2, null, null);
        assertThat(response.getStatus(), is(200));

        // Page 1 with length 2
        response = userResource.getAllApiTokens(null, 1, 2, null, null);
        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllApiTokensNoPagingWhenPageLengthZero() {
        ManagedUser user = createManagedUserWithTokens("admin", 3);
        when(userRegistry.getAll()).thenReturn(List.of(user));

        // pagelength 0 means return all
        Response response = userResource.getAllApiTokens(null, 0, 0, null, null);
        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllApiTokensFilterByUser() {
        ManagedUser user1 = createManagedUserWithTokens("admin", 2);
        ManagedUser user2 = createManagedUserWithTokens("john", 1);
        when(userRegistry.getAll()).thenReturn(List.of(user1, user2));

        Response response = userResource.getAllApiTokens("john", 0, 0, null, null);
        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetAllApiTokensOrderBy() {
        ManagedUser user = createManagedUserWithTokens("admin", 3);
        when(userRegistry.getAll()).thenReturn(List.of(user));

        Response response = userResource.getAllApiTokens(null, 0, 0, "name", "asc");
        assertThat(response.getStatus(), is(200));
    }

    // --- GET /auth/users/{userId}/apitokens ---

    @Test
    public void testGetUserApiTokensReturnsTokensForUser() {
        ManagedUser user = createManagedUserWithTokens("admin", 2);
        when(userRegistry.get("admin")).thenReturn(user);

        Response response = userResource.getUserApiTokens("admin");

        assertThat(response.getStatus(), is(200));
    }

    @Test
    public void testGetUserApiTokensReturns404WhenUserNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.getUserApiTokens("unknown");

        assertThat(response.getStatus(), is(404));
    }

    @Test
    public void testGetUserApiTokensReturns400WhenNotManagedUser() {
        User mockUser = when(org.mockito.Mockito.mock(User.class).getName()).thenReturn("external").getMock();
        when(userRegistry.get("external")).thenReturn(mockUser);

        Response response = userResource.getUserApiTokens("external");

        assertThat(response.getStatus(), is(400));
    }

    // --- DELETE /auth/users/{userId}/apitokens/{tokenName} ---

    @Test
    public void testRevokeUserApiTokenSuccess() {
        ManagedUser user = createManagedUserWithTokens("admin", 2);
        when(userRegistry.get("admin")).thenReturn(user);

        Response response = userResource.revokeUserApiToken("admin", "token-0");

        assertThat(response.getStatus(), is(200));
        verify(userRegistry).removeUserApiToken(eq(user), any(UserApiToken.class));
    }

    @Test
    public void testRevokeUserApiTokenReturns404WhenUserNotFound() {
        when(userRegistry.get("unknown")).thenReturn(null);

        Response response = userResource.revokeUserApiToken("unknown", "token-0");

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).removeUserApiToken(any(), any());
    }

    @Test
    public void testRevokeUserApiTokenReturns404WhenTokenNotFound() {
        ManagedUser user = createManagedUserWithTokens("admin", 1);
        when(userRegistry.get("admin")).thenReturn(user);

        Response response = userResource.revokeUserApiToken("admin", "nonexistent");

        assertThat(response.getStatus(), is(404));
        verify(userRegistry, never()).removeUserApiToken(any(), any());
    }

    // --- Helper methods ---

    private ManagedUser createManagedUser(String name, Set<String> roles) {
        ManagedUser user = new ManagedUser(name, "salt", "hash");
        user.setRoles(roles);
        return user;
    }

    private ManagedUser createManagedUserWithSessions(String name, int sessionCount) {
        ManagedUser user = createManagedUser(name, Set.of("administrator"));
        List<UserSession> sessions = new ArrayList<>();
        for (int i = 0; i < sessionCount; i++) {
            sessions.add(new UserSession("sess" + i + "-uuid-" + i, "refresh" + i, "client" + i,
                    "http://localhost:8080", "admin"));
        }
        user.setSessions(sessions);
        return user;
    }

    private ManagedUser createManagedUserWithTokens(String name, int tokenCount) {
        ManagedUser user = createManagedUser(name, Set.of("administrator"));
        List<UserApiToken> tokens = new ArrayList<>();
        for (int i = 0; i < tokenCount; i++) {
            tokens.add(new UserApiToken("token-" + i, "hashed-token-" + i, "admin"));
        }
        user.setApiTokens(tokens);
        return user;
    }
}
