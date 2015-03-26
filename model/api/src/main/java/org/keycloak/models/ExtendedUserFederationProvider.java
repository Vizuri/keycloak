/**
 * 
 */
package org.keycloak.models;

import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserFederationProvider;

/**
 * @author jli
 *
 */
public interface ExtendedUserFederationProvider extends UserFederationProvider {
	RoleModel createRole(RealmModel realm, RoleModel role);
	void removeRole(RealmModel realm, RoleModel role);
	void grantRole(RealmModel realm, UserModel user, RoleModel role);
	void revokeRole(RealmModel realm, UserModel user, RoleModel role);
}
