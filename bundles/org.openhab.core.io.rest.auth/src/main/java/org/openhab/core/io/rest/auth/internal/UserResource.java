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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.ManagedUser;
import org.openhab.core.auth.Role;
import org.openhab.core.auth.User;
import org.openhab.core.auth.UserRegistry;
import org.openhab.core.io.rest.JSONResponse;
import org.openhab.core.io.rest.RESTConstants;
import org.openhab.core.io.rest.RESTResource;
import org.openhab.core.io.rest.Stream2JSONInputStream;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.JaxrsWhiteboardConstants;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JSONRequired;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsApplicationSelect;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsName;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * This resource provides REST endpoints for user management operations.
 * <p>
 * All endpoints require administrator privileges. The resource exposes the capabilities of the
 * {@link UserRegistry} which are otherwise only accessible via Karaf console commands.
 * <p>
 * Supported operations:
 * <ul>
 * <li>List all registered users</li>
 * <li>Get a specific user by name</li>
 * <li>Create a new user with roles</li>
 * <li>Update a user's role assignments</li>
 * <li>Change a user's password</li>
 * <li>Delete a user (with self-deletion protection)</li>
 * </ul>
 *
 * @author Gabor Bicskei - Initial contribution
 */
@Component(service = { RESTResource.class, UserResource.class })
@JaxrsResource
@JaxrsName(UserResource.PATH_USERS)
@JaxrsApplicationSelect("(" + JaxrsWhiteboardConstants.JAX_RS_NAME + "=" + RESTConstants.JAX_RS_NAME + ")")
@JSONRequired
@Path(UserResource.PATH_USERS)
@RolesAllowed({ Role.ADMIN })
@SecurityRequirement(name = "oauth2", scopes = { "admin" })
@Tag(name = TokenResource.PATH_AUTH)
@NonNullByDefault
public class UserResource implements RESTResource {

    private final Logger logger = LoggerFactory.getLogger(UserResource.class);

    /** The URI path to this resource */
    public static final String PATH_USERS = "auth/users";

    /** The set of valid role names that can be assigned to users */
    private static final Set<String> VALID_ROLES = Set.of(Role.ADMIN, Role.USER);

    private final UserRegistry userRegistry;

    @Activate
    public UserResource(final @Reference UserRegistry userRegistry) {
        this.userRegistry = userRegistry;
    }

    /**
     * Returns all registered users as a JSON array.
     *
     * @return a {@link Response} containing a JSON array of {@link UserDTO} objects
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "getUsers", summary = "Get all registered users.", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserDTO.class)))) })
    public Response getUsers() {
        Stream<UserDTO> users = userRegistry.getAll().stream().map(UserDTO::new);
        return Response.ok(new Stream2JSONInputStream(users)).build();
    }

    /**
     * Returns a specific user identified by the given user ID (username).
     *
     * @param userId the username to look up
     * @return a {@link Response} containing the {@link UserDTO}, or 404 if not found
     */
    @GET
    @Path("/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "getUserById", summary = "Get a specific user by user ID.", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "404", description = "User not found") })
    public Response getUser(@PathParam("userId") String userId) {
        User user = userRegistry.get(userId);
        if (user == null) {
            return JSONResponse.createErrorResponse(Status.NOT_FOUND, "User not found: " + userId);
        }
        return JSONResponse.createResponse(Status.OK, new UserDTO(user), null);
    }

    /**
     * Creates a new user with the given name, password, and roles.
     * <p>
     * The roles must be valid framework roles ({@link Role#ADMIN} or {@link Role#USER}).
     * Returns 409 if a user with the given name already exists.
     *
     * @param data the {@link CreateUserDTO} containing name, password, and roles
     * @return a {@link Response} containing the created {@link UserDTO}, or an error response
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "createUser", summary = "Create a new user.", responses = {
            @ApiResponse(responseCode = "201", description = "User created", content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "400", description = "Missing or invalid fields"),
            @ApiResponse(responseCode = "409", description = "User already exists") })
    public Response createUser(CreateUserDTO data) {
        String name = data.name;
        String password = data.password;
        Collection<String> roles = data.roles;

        if (name == null || name.isEmpty()) {
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST, "A name is required.");
        }
        if (password == null || password.isEmpty()) {
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST, "A password is required.");
        }
        if (roles == null || roles.isEmpty()) {
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST, "At least one role is required.");
        }
        if (!VALID_ROLES.containsAll(roles)) {
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST,
                    "Invalid roles. Allowed values: " + VALID_ROLES);
        }

        if (userRegistry.get(name) != null) {
            return JSONResponse.createErrorResponse(Status.CONFLICT, "A user with name '" + name + "' already exists.");
        }

        User newUser = userRegistry.register(name, password, new HashSet<>(roles));
        logger.info("Created user '{}'", name);
        return JSONResponse.createResponse(Status.CREATED, new UserDTO(newUser), null);
    }

    /**
     * Replaces all roles of a user with the provided set of roles.
     * <p>
     * The roles must be valid framework roles ({@link Role#ADMIN} or {@link Role#USER}).
     *
     * @param userId the username of the user to update
     * @param roles the new set of roles to assign
     * @return a {@link Response} containing the updated {@link UserDTO}, or an error response
     */
    @PUT
    @Path("/{userId}/roles")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "updateUserRoles", summary = "Update the roles of a user (replaces all existing roles).", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "400", description = "Invalid roles"),
            @ApiResponse(responseCode = "404", description = "User not found") })
    public Response updateUserRoles(@PathParam("userId") String userId, Set<String> roles) {
        if (!VALID_ROLES.containsAll(roles)) {
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST,
                    "Invalid roles. Allowed values: " + VALID_ROLES);
        }

        User user = userRegistry.get(userId);
        if (user == null) {
            return JSONResponse.createErrorResponse(Status.NOT_FOUND, "User not found: " + userId);
        }
        if (!(user instanceof ManagedUser managedUser)) {
            return JSONResponse.createErrorResponse(Status.INTERNAL_SERVER_ERROR,
                    "Cannot update roles for user: " + userId);
        }

        managedUser.setRoles(new HashSet<>(roles));
        userRegistry.update(managedUser);
        logger.info("Updated roles for user '{}' to {}", userId, roles);
        return JSONResponse.createResponse(Status.OK, new UserDTO(managedUser), null);
    }

    /**
     * Changes the password of the specified user.
     *
     * @param userId the username of the user whose password should be changed
     * @param data the {@link ChangePasswordDTO} containing the new password
     * @return a {@link Response} with status 200 on success, or an error response
     */
    @PUT
    @Path("/{userId}/password")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "changeUserPassword", summary = "Change the password of a user.", responses = {
            @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "400", description = "Missing required fields"),
            @ApiResponse(responseCode = "404", description = "User not found") })
    public Response changeUserPassword(@PathParam("userId") String userId, ChangePasswordDTO data) {
        String newPassword = data.newPassword;
        if (newPassword == null || newPassword.isEmpty()) {
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST, "A new password is required.");
        }

        User user = userRegistry.get(userId);
        if (user == null) {
            return JSONResponse.createErrorResponse(Status.NOT_FOUND, "User not found: " + userId);
        }

        userRegistry.changePassword(user, newPassword);
        logger.info("Changed password for user '{}'", userId);
        return Response.ok().build();
    }

    /**
     * Deletes a user from the registry.
     * <p>
     * A user cannot delete their own account (self-deletion protection).
     *
     * @param userId the username of the user to delete
     * @param securityContext the JAX-RS security context to identify the current user
     * @return a {@link Response} with status 200 on success, or an error response
     */
    @DELETE
    @Path("/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "deleteUser", summary = "Delete a user.", responses = {
            @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "400", description = "Cannot delete own account"),
            @ApiResponse(responseCode = "404", description = "User not found") })
    public Response deleteUser(@PathParam("userId") String userId, @Context SecurityContext securityContext) {
        User user = userRegistry.get(userId);
        if (user == null) {
            return JSONResponse.createErrorResponse(Status.NOT_FOUND, "User not found: " + userId);
        }

        if (securityContext.getUserPrincipal() != null
                && user.getName().equals(securityContext.getUserPrincipal().getName())) {
            logger.warn("Rejected attempt to delete own account '{}'", userId);
            return JSONResponse.createErrorResponse(Status.BAD_REQUEST, "Cannot delete your own account.");
        }

        userRegistry.remove(userId);
        logger.info("Deleted user '{}'", userId);
        return Response.ok().build();
    }
}
