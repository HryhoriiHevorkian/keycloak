package org.keycloak.services.clientpolicy;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;

public class DynamicClientRegisteredContext implements ClientUpdateContext {

    private final ClientRegistrationContext context;
    private JsonWebToken token;
    private UserModel user;
    private ClientModel client;

    public DynamicClientRegisteredContext(ClientRegistrationContext context,
                                          JsonWebToken token, RealmModel realm) {
        this.context = context;
        this.token = token;
        if (token != null) {
            if (token.getSubject() != null) {
                this.user = context.getSession().users().getUserById(token.getSubject(), realm);
            }
            if (token.getIssuedFor() != null) {
                this.client = realm.getClientByClientId(token.getIssuedFor());
            }
        }
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.REGISTERED;
    }

    @Override
    public ClientRepresentation getProposedClientRepresentation() {
        return context.getClient();
    }

    @Override
    public ClientModel getAuthenticatedClient() {
        return client;
    }

    @Override
    public UserModel getAuthenticatedUser() {
        return user;
    }

    @Override
    public JsonWebToken getToken() {
        return token;
    }
}
