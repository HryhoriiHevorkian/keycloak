package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.resources.admin.AdminAuth;

public class AdminClientRegisteredContext implements ClientUpdateContext {

    private final ClientRepresentation clientRepresentation;
    private final AdminAuth adminAuth;

    public AdminClientRegisteredContext(ClientRepresentation clientRepresentation,
                                        AdminAuth adminAuth) {
        this.clientRepresentation = clientRepresentation;
        this.adminAuth = adminAuth;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.REGISTERED;
    }

    @Override
    public ClientRepresentation getProposedClientRepresentation() {
        return clientRepresentation;
    }

    @Override
    public ClientModel getAuthenticatedClient() {
        return adminAuth.getClient();
    }

    @Override
    public UserModel getAuthenticatedUser() {
        return adminAuth.getUser();
    }

    @Override
    public JsonWebToken getToken() {
        return adminAuth.getToken();
    }
}
