package org.keycloak.representations.idm;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ApplicationRepresentation {
    protected String self; // link
    protected String id;
    protected String name;
    protected String adminUrl;
    protected boolean surrogateAuthRequired;
    protected boolean useRealmMappings;
    protected boolean enabled;
    protected List<CredentialRepresentation> credentials;
    protected List<RoleRepresentation> roles;
    protected List<RoleMappingRepresentation> roleMappings;
    protected List<ScopeMappingRepresentation> scopeMappings;

    public String getSelf() {
        return self;
    }

    public void setSelf(String self) {
        this.self = self;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isSurrogateAuthRequired() {
        return surrogateAuthRequired;
    }

    public void setSurrogateAuthRequired(boolean surrogateAuthRequired) {
        this.surrogateAuthRequired = surrogateAuthRequired;
    }

    public List<RoleRepresentation> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleRepresentation> roles) {
        this.roles = roles;
    }

    public ApplicationRepresentation role(RoleRepresentation role) {
        if (this.roles == null) this.roles = new ArrayList<RoleRepresentation>();
        this.roles.add(role);
        return this;
    }


    public ApplicationRepresentation role(String role, String description) {
        if (this.roles == null) this.roles = new ArrayList<RoleRepresentation>();
        this.roles.add(new RoleRepresentation(role, description));
        return this;
    }

    public List<RoleMappingRepresentation> getRoleMappings() {
        return roleMappings;
    }

    public RoleMappingRepresentation roleMapping(String username) {
        RoleMappingRepresentation mapping = new RoleMappingRepresentation();
        mapping.setUsername(username);
        if (roleMappings == null) roleMappings = new ArrayList<RoleMappingRepresentation>();
        roleMappings.add(mapping);
        return mapping;
    }

    public List<ScopeMappingRepresentation> getScopeMappings() {
        return scopeMappings;
    }

    public ScopeMappingRepresentation scopeMapping(String username) {
        ScopeMappingRepresentation mapping = new ScopeMappingRepresentation();
        mapping.setUsername(username);
        if (scopeMappings == null) scopeMappings = new ArrayList<ScopeMappingRepresentation>();
        scopeMappings.add(mapping);
        return mapping;
    }

    public String getAdminUrl() {
        return adminUrl;
    }

    public void setAdminUrl(String adminUrl) {
        this.adminUrl = adminUrl;
    }

    public List<CredentialRepresentation> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<CredentialRepresentation> credentials) {
        this.credentials = credentials;
    }

    public ApplicationRepresentation credential(String type, String value) {
        if (this.credentials == null) credentials = new ArrayList<CredentialRepresentation>();
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(type);
        cred.setValue(value);
        credentials.add(cred);
        return this;
    }

    public boolean isUseRealmMappings() {
        return useRealmMappings;
    }

    public void setUseRealmMappings(boolean useRealmMappings) {
        this.useRealmMappings = useRealmMappings;
    }
}