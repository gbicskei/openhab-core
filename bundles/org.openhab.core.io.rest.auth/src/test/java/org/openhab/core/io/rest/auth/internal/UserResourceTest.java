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
import org.openhab.core.auth.UserRegistry;

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

    // --- Helper methods ---

    private ManagedUser createManagedUser(String name, Set<String> roles) {
        ManagedUser user = new ManagedUser(name, "salt", "hash");
        user.setRoles(roles);
        return user;
    }
}
