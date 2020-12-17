package org.keycloak.services.clientpolicy.executor;

import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.*;
import org.keycloak.services.clientregistration.policy.impl.ClientScopesClientRegistrationPolicyFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientScopesClientEnforceExecutor extends AbstractAugumentingClientRegistrationPolicyExecutor {

    private final RealmModel realm;

    public ClientScopesClientEnforceExecutor(KeycloakSession session, ComponentModel componentModel) {
        super(session, componentModel);
        this.realm = session.realms().getRealm(componentModel.getParentId());
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

            case REGISTER:
                if (context instanceof AdminClientRegisterContext || context instanceof DynamicClientRegisterContext) {
                    ClientUpdateContext adminClientRegisterContext = (ClientUpdateContext) context;

                    Set<String> requestedDefaultScopeNames = adminClientRegisterContext.getAuthenticatedClient().getClientScopes(true, false).keySet();
                    Set<String> requestedOptionalScopeNames = adminClientRegisterContext.getAuthenticatedClient().getClientScopes(false, false).keySet();

                    Set<String> allowedDefaultScopeNames = getAllowedScopeNames(realm, true);
                    Set<String> allowedOptionalScopeNames = getAllowedScopeNames(realm, false);

                    checkClientScopesAllowed(requestedDefaultScopeNames, allowedDefaultScopeNames);
                    checkClientScopesAllowed(requestedOptionalScopeNames, allowedOptionalScopeNames);
                }
                break;

            case UPDATE:
                if (context instanceof AdminClientRegisterContext || context instanceof DynamicClientRegisterContext) {
                    ClientUpdateContext adminClientUpdateContext = (ClientUpdateContext) context;

                    Set<String> requestedDefaultScopeNamesUpdate = adminClientUpdateContext.getAuthenticatedClient().getClientScopes(true, false).keySet();
                    Set<String> requestedOptionalScopeNamesUpdate = adminClientUpdateContext.getAuthenticatedClient().getClientScopes(false, false).keySet();

                    // Allow scopes, which were already presented before
                    if (!requestedDefaultScopeNamesUpdate.isEmpty()) {
                        requestedDefaultScopeNamesUpdate.removeAll(adminClientUpdateContext.getAuthenticatedClient().getClientScopes(true, false).keySet());
                    }
                    if (!requestedOptionalScopeNamesUpdate.isEmpty()) {
                        requestedOptionalScopeNamesUpdate.removeAll(adminClientUpdateContext.getAuthenticatedClient().getClientScopes(false, false).keySet());
                    }

                    Set<String> allowedDefaultScopeNamesUpdate = getAllowedScopeNames(realm, true);
                    Set<String> allowedOptionalScopeNamesUpdate = getAllowedScopeNames(realm, false);

                    checkClientScopesAllowed(requestedDefaultScopeNamesUpdate, allowedDefaultScopeNamesUpdate);
                    checkClientScopesAllowed(requestedOptionalScopeNamesUpdate, allowedOptionalScopeNamesUpdate);
                }
                break;
        }
    }

    private void checkClientScopesAllowed(Set<String> requestedScopes, Set<String> allowedScopes) throws ClientPolicyException {
        if (requestedScopes != null) {
            for (String requested : requestedScopes) {
                if (!allowedScopes.contains(requested)) {
                    logger.warnf("Requested scope '%s' not trusted in the list: %s", requested, allowedScopes.toString());
                    throw new ClientPolicyException(Errors.NOT_ALLOWED, "Not permitted to use specified clientScope");
                }
            }
        }
    }

    private Set<String> getAllowedScopeNames(RealmModel realm, boolean defaultScopes) {
        Set<String> allAllowed = new HashSet<>();

        // Add client scopes allowed by config
        List<String> allowedScopesConfig = componentModel.getConfig().getList(ClientScopesClientRegistrationPolicyFactory.ALLOWED_CLIENT_SCOPES);
        if (allowedScopesConfig != null) {
            allAllowed.addAll(allowedScopesConfig);
        }

        // If allowDefaultScopes, then realm default scopes are allowed as default scopes (+ optional scopes are allowed as optional scopes)
        boolean allowDefaultScopes = componentModel.get(ClientScopesClientRegistrationPolicyFactory.ALLOW_DEFAULT_SCOPES, true);
        if (allowDefaultScopes) {
            List<String> scopeNames = realm.getDefaultClientScopes(defaultScopes).stream()
                                              .map(ClientScopeModel::getName)
                                              .collect(Collectors.toList());

            allAllowed.addAll(scopeNames);
        }

        return allAllowed;
    }


}
