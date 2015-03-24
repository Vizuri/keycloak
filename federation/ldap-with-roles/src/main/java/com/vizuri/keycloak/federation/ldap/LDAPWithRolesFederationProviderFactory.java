package com.vizuri.keycloak.federation.ldap;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.federation.ldap.LDAPFederationProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserFederationProviderModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.picketlink.PartitionManagerProvider;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.RelationshipManager;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.IdentityQuery;

/**
 * @author <a href="mailto:jli@vizuri.com">Jiehuan Li</a>
 * @version $Revision: 1 $
 */
public class LDAPWithRolesFederationProviderFactory extends LDAPFederationProviderFactory {
	private static final Logger logger = Logger.getLogger(LDAPWithRolesFederationProviderFactory.class);
    public static final String PROVIDER_NAME = "ldap-with-roles";

    private static final Set<String> configOptions = new HashSet<String>();
    
    @Override
    public LDAPWithRolesFederationProvider getInstance(KeycloakSession session, UserFederationProviderModel model) {
        PartitionManagerProvider idmProvider = session.getProvider(PartitionManagerProvider.class);
        PartitionManager partition = idmProvider.getPartitionManager(model);
        return new LDAPWithRolesFederationProvider(session, model, partition);
    }
    
    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public void syncAllUsers(KeycloakSessionFactory sessionFactory, String realmId, UserFederationProviderModel model) {
        logger.infof("Sync all users from LDAP to local store: realm: %s, federation provider: %s, current time: " + new Date(), realmId, model.getDisplayName());

        PartitionManagerProvider idmProvider = sessionFactory.create().getProvider(PartitionManagerProvider.class);
        PartitionManager partitionMgr = idmProvider.getPartitionManager(model);
        IdentityManager idm = partitionMgr.createIdentityManager();
        IdentityQuery<User> userQuery = idm.createIdentityQuery(User.class);
        IdentityQuery<Role> roleQuery = idm.createIdentityQuery(Role.class);
        RelationshipManager rm = partitionMgr.createRelationshipManager();
        syncImpl(sessionFactory, userQuery, roleQuery, rm, realmId, model);

        // TODO: Remove all existing keycloak users, which have federation links, but are not in LDAP. Perhaps don't check users, which were just added or updated during this sync?
    }
    
    protected void syncImpl(KeycloakSessionFactory sessionFactory, IdentityQuery<User> userQuery, IdentityQuery<Role> roleQuery, final RelationshipManager relationshipManager, final String realmId, final UserFederationProviderModel fedModel) {
        boolean pagination = Boolean.parseBoolean(fedModel.getConfig().get(LDAPConstants.PAGINATION));

        if (pagination) {
            String pageSizeConfig = fedModel.getConfig().get(LDAPConstants.BATCH_SIZE_FOR_SYNC);
            int pageSize = pageSizeConfig!=null ? Integer.parseInt(pageSizeConfig) : LDAPConstants.DEFAULT_BATCH_SIZE_FOR_SYNC;
            
          //sync roles.
            boolean nextPage = true;
            while (nextPage) {
                roleQuery.setLimit(pageSize);
                final List<Role> roles = roleQuery.getResultList();
                nextPage = roleQuery.getPaginationContext() != null;

                KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

                    @Override
                    public void run(KeycloakSession session) {
                        importPicketlinkRoles(session, realmId, fedModel, roles);
                    }

                });
            }
            
            //sync users.
            nextPage = true;
            while (nextPage) {
                userQuery.setLimit(pageSize);
                final List<User> users = userQuery.getResultList();
                nextPage = userQuery.getPaginationContext() != null;

                KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

                    @Override
                    public void run(KeycloakSession session) {
                        importPicketlinkUsers(session, realmId, fedModel, users, relationshipManager);
                    }

                });
            }            
        } else {
            // LDAP pagination not available. Do everything in single transaction
        	
        	//sync roles.
            final List<Role> roles = roleQuery.getResultList();
            KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

                @Override
                public void run(KeycloakSession session) {
                    importPicketlinkRoles(session, realmId, fedModel, roles);
                }

            });
        	
        	//sync users.
            final List<User> users = userQuery.getResultList();
            KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

                @Override
                public void run(KeycloakSession session) {
                    importPicketlinkUsers(session, realmId, fedModel, users, relationshipManager);
                }

            });
            
        }
    }
    
    protected void importPicketlinkRoles(KeycloakSession session, String realmId, UserFederationProviderModel fedModel, List<Role> roles) {
        RealmModel realm = session.realms().getRealm(realmId);
        LDAPWithRolesFederationProvider ldapWithRolesFedProvider = getInstance(session, fedModel);
        ldapWithRolesFedProvider.importPicketlinkRoles(realm, roles, fedModel);
    }
    
    protected void importPicketlinkUsers(KeycloakSession session, String realmId, UserFederationProviderModel fedModel, List<User> users, RelationshipManager relationshipManager) {
        RealmModel realm = session.realms().getRealm(realmId);
        LDAPWithRolesFederationProvider ldapWithRolesFedProvider = getInstance(session, fedModel);
        ldapWithRolesFedProvider.importPicketlinkUsers(realm, users, fedModel, relationshipManager);
    }
}
