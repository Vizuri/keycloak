package com.vizuri.keycloak.federation.ldap;

import org.keycloak.models.ModelReadOnlyException;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.RoleModelDelegate;

/**
 * @author <a href="mailto:jli@vizuri.com">Jiehuan Li</a>
 * @version $Revision: 1 $
 */
public class ReadonlyLDAPRoleModelDelegate extends RoleModelDelegate implements RoleModel {

    protected LDAPWithRolesFederationProvider provider;

    public ReadonlyLDAPRoleModelDelegate(RoleModel delegate, LDAPWithRolesFederationProvider provider) {
        super(delegate);
        this.provider = provider;
    }

    @Override
    public void setName(String rolename) {
        throw new ModelReadOnlyException("Federated storage is not writable");
    }

}
