package com.vizuri.keycloak.federation.ldap;

import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.federation.ldap.LDAPFederationProvider;
import org.keycloak.federation.ldap.LDAPUtils;
import org.keycloak.models.ExtendedUserFederationProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserFederationProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserFederationProvider.EditMode;
import org.picketlink.idm.IdentityManagementException;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.RelationshipManager;
import org.picketlink.idm.model.basic.Grant;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.RelationshipQuery;

/**
 * @author <a href="mailto:jli@vizuri.com">Jiehuan Li</a>
 * @version $Revision: 1 $
 */
public class LDAPWithRolesFederationProvider extends LDAPFederationProvider implements ExtendedUserFederationProvider {
	private static final Logger logger = Logger.getLogger(LDAPWithRolesFederationProvider.class);
	
    public LDAPWithRolesFederationProvider(KeycloakSession session, UserFederationProviderModel model, PartitionManager partitionManager) {
        super(session, model, partitionManager);
    }
    
    protected void importPicketlinkRoles(RealmModel realm, List<Role> roles, UserFederationProviderModel fedModel) {
        for (Role picketlinkRole : roles) {
            String rolename = picketlinkRole.getName();
            //TODO: Not involving session in looking up currentRole may have transaction implications, need to dig deeper.
//            RoleModel currentRole = session.roleStorage().getRoleByRolename(rolename, realm);
            RoleModel currentRole = null;
            currentRole = getRole(realm, rolename);
            
            if (currentRole == null) {
                // Add new role to Keycloak
                importRoleFromPicketlink(realm, picketlinkRole);
                logger.debugf("Added new role from LDAP: %s", rolename);
            } else {
            	// TODO: Add the linkage to federation by federation link and ldap attribute on RoleModel to make sure this role is indeed backed by federation.
//                if ((fedModel.getId().equals(currentRole.getFederationLink())) && (picketlinkRole.getId().equals(currentRole.getAttribute(LDAPFederationProvider.LDAP_ID)))) {
//                    // Update keycloak role
//                    logger.debugf("Nothing to update for role from LDAP: %s", currentRole.getRolename());
//                } else {
//                    logger.warnf("Role '%s' is not updated during sync as this role is not linked to federation provider '%s'", rolename, fedModel.getDisplayName());
//                }
            }
        }
    }

	private RoleModel getRole(RealmModel realm, String rolename) {
		Set<RoleModel> allRoles = realm.getRoles();
		for (RoleModel role : allRoles) {
			if (role.getName().equals(rolename)) {
				return role;
			}
		}
		return null;
	}
    
    protected RoleModel importRoleFromPicketlink(RealmModel realm, Role picketlinkRole) {

        if (picketlinkRole.getName() == null) {
            throw new ModelException("Role returned from LDAP has null rolename! Check configuration of your LDAP mappings. ID of role from LDAP: " + picketlinkRole.getId());
        }

        //TODO: Not involving session in looking up currentRole may have transaction implications, need to dig deeper.
//        RoleModel imported = session.roleStorage().addRole(realm, picketlinkRole.getName());
        RoleModel imported = realm.addRole(picketlinkRole.getName());
        //TODO: implement setAttribute on RoleModel.
//        imported.setAttribute(LDAP_ID, picketlinkRole.getId());
        return proxy(imported);
    }
    
    public RoleModel proxy(RoleModel local) {
        switch (editMode) {
            case READ_ONLY:
               return new ReadonlyLDAPRoleModelDelegate(local, this);
            case WRITABLE:
               return new WritableLDAPRoleModelDelegate(local, this);
            case UNSYNCED:
               return new UnsyncedLDAPRoleModelDelegate(local, this);
        }
       return local;
   }
    
    protected void importPicketlinkUsers(RealmModel realm, List<User> users, UserFederationProviderModel fedModel, RelationshipManager relationshipManager) {
        for (User picketlinkUser : users) {
            String username = picketlinkUser.getLoginName();
            UserModel currentUser = session.userStorage().getUserByUsername(username, realm);

            if (currentUser == null) {
                // Add new user to Keycloak
                importUserFromPicketlink(realm, picketlinkUser);
                logger.debugf("Added new user from LDAP: %s", username);
                currentUser = session.userStorage().getUserByUsername(username, realm);
            } else {
                if ((fedModel.getId().equals(currentUser.getFederationLink())) && (picketlinkUser.getId().equals(currentUser.getAttribute(LDAPFederationProvider.LDAP_ID)))) {
                    // Update keycloak user
                    String email = (picketlinkUser.getEmail() != null && picketlinkUser.getEmail().trim().length() > 0) ? picketlinkUser.getEmail() : null;
                    currentUser.setEmail(email);
                    currentUser.setFirstName(picketlinkUser.getFirstName());
                    currentUser.setLastName(picketlinkUser.getLastName());
                    logger.debugf("Updated user from LDAP: %s", currentUser.getUsername());
                } else {
                    logger.warnf("User '%s' is not updated during sync as he is not linked to federation provider '%s'", username, fedModel.getDisplayName());
                }
            }
            
            // Deal with memberships            
            RelationshipQuery<Grant> grantQuery = relationshipManager.createRelationshipQuery(Grant.class);            
            grantQuery.setParameter(Grant.ASSIGNEE, picketlinkUser);
            List<Grant> grants = grantQuery.getResultList();

            // Remove all keycloak existing realm role mappings for this user
            for (RoleModel role : currentUser.getRealmRoleMappings()) {
            	currentUser.deleteRoleMapping(role);
            }
            
            for (Grant grant : grants) {
            	// Iterating over the user roles
            	Role picketlinkRole = grant.getRole();
            	if (picketlinkRole != null) {
            		RoleModel role = getRole(realm, picketlinkRole.getName());
            		if (role != null)
            			currentUser.grantRole(role);
            		else
            			logger.errorf("Can not find matching keycloak role for picketlink role '%s' for user '%s'", picketlinkRole.getName(), username);
            	} else {
            		logger.errorf("Picketlink returned a 'null' role in grant for user '%s'", username);
            	}
            }
        }
    }

	@Override
	public RoleModel registerRole(RealmModel realm, RoleModel role) {
		if (editMode == EditMode.READ_ONLY || editMode == EditMode.UNSYNCED) throw new IllegalStateException("Role creation is not supported by this ldap server");

        try {
            Role picketlinkRole = LDAPUtils.addRole(this.partitionManager, role.getName());
          //TODO: imiplement role.setAttribute method.
//            role.setAttribute(LDAP_ID, picketlinkRole.getId());
            return proxy(role);
        } catch (IdentityManagementException ie) {
            throw convertIDMException(ie);
        }
	}
	
	private ModelException convertIDMException(IdentityManagementException ie) {
        Throwable realCause = ie;
        while (realCause.getCause() != null) {
            realCause = realCause.getCause();
        }

        // Use the message from the realCause
        return new ModelException(realCause.getMessage(), ie);
    }

	@Override
	public void grantRole(RealmModel realm, UserModel user, RoleModel role) {
		if (editMode == EditMode.READ_ONLY || editMode == EditMode.UNSYNCED) throw new IllegalStateException("Role mapping synchronization to ldap is not supported by this ldap server");

        try {
            LDAPUtils.grantRole(this.partitionManager, user.getUsername(), role.getName());
        } catch (IdentityManagementException ie) {
            throw convertIDMException(ie);
        }
	}

	@Override
	public void revokeRole(RealmModel realm, UserModel user, RoleModel role) {
		if (editMode == EditMode.READ_ONLY || editMode == EditMode.UNSYNCED) throw new IllegalStateException("Role mapping synchronization to ldap is not supported by this ldap server");

        try {
            LDAPUtils.revokeRole(this.partitionManager, user.getUsername(), role.getName());
        } catch (IdentityManagementException ie) {
            throw convertIDMException(ie);
        }
	}

	@Override
	public void deleteRole(RealmModel realm, RoleModel role) {
		if (editMode == EditMode.READ_ONLY || editMode == EditMode.UNSYNCED) throw new IllegalStateException("Role deletion is not supported by this ldap server");

        try {
        	//TODO: check if this role is actually linked to user federation, and only delete it if it is.
            Role picketlinkRole = LDAPUtils.deleteRole(this.partitionManager, role.getName());
        } catch (IdentityManagementException ie) {
            throw convertIDMException(ie);
        }
	}

}
