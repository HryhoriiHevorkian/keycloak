package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientUpdateContext;

public class ClientDisabledClientEnforceExecutor implements ClientPolicyExecutorProvider {

    private static final Logger logger = Logger.getLogger(ClientDisabledClientEnforceExecutor.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientDisabledClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case REGISTERED:
                ((ClientUpdateContext) context).getAuthenticatedClient().setEnabled(false);
                break;
            case UPDATE:
                ClientUpdateContext clientUpdateContext = (ClientUpdateContext) context;
                ClientModel clientModel = clientUpdateContext.getAuthenticatedClient();

                boolean isEnabled = clientModel.isEnabled();
                boolean newEnabled = clientUpdateContext.getClientToBeUpdated().isEnabled();

                if (!isEnabled && newEnabled) {
                    throw new ClientPolicyException(Errors.NOT_ALLOWED, "Not permitted to enable client");
                }
            default:
                return;
        }
    }
}
