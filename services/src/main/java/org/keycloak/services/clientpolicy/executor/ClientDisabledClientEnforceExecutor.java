package org.keycloak.services.clientpolicy.executor;

import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.AdminClientRegisterContext;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ClientDisabledClientEnforceExecutor extends AbstractAugumentingClientRegistrationPolicyExecutor {

    public ClientDisabledClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
    }

    @Override
    protected void augment(ClientRepresentation rep) {

    }

    @Override
    protected void validate(ClientRepresentation rep) {

    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        super.executeOnEvent(context);

        switch (context.getEvent()) {

            case REGISTERED:
                AdminClientRegisterContext adminClientRegisterContext = (AdminClientRegisterContext) context;
                adminClientRegisterContext.getAuthenticatedClient().setEnabled(false);
                break;

            case UPDATE:
                ClientUpdateContext clientUpdateContext = (ClientUpdateContext) context;
                ClientModel clientModel = clientUpdateContext.getAuthenticatedClient();

                boolean isEnabled = clientModel.isEnabled();
                boolean newEnabled = clientUpdateContext.getClientToBeUpdated().isEnabled();

                if (!isEnabled && newEnabled) {
                    throw new ClientPolicyException(Errors.NOT_ALLOWED, "Not permitted to enable client");
                }

                break;
        }
    }

}
