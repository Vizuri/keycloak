package org.keycloak.services.resources.admin;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.NotFoundException;
import org.keycloak.models.ApplicationModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserFederationProvider;
import org.keycloak.models.UserFederationProviderFactory;
import org.keycloak.models.UserFederationProviderModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.resources.flows.Flows;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:jli@vizuri.com">Jiehuan Li</a>
 * @version $Revision: 1 $
 */
public class RoleContainerResource extends RoleResource {
	private static final Logger logger = Logger.getLogger(RoleContainerResource.class);
    private final RealmModel realm;
    private final RealmAuth auth;
    protected RoleContainerModel roleContainer;
    
    @Context
    protected KeycloakSession session;

    public RoleContainerResource(RealmModel realm, RealmAuth auth, RoleContainerModel roleContainer) {
        super(realm);
        this.realm = realm;
        this.auth = auth;
        this.roleContainer = roleContainer;
    }

    /**
     * List all roles for this realm or application
     *
     * @return
     */
    @GET
    @NoCache
    @Produces("application/json")
    public List<RoleRepresentation> getRoles() {
        auth.requireAny();

        Set<RoleModel> roleModels = roleContainer.getRoles();
        List<RoleRepresentation> roles = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : roleModels) {
        	String federationLink = roleModel.getFederationLink();
        	if ( federationLink == null)
        		roles.add(ModelToRepresentation.toRepresentation(roleModel));
        	else {
        		for (UserFederationProviderModel federation : realm.getUserFederationProviders()) {
            		if (federation.getId().equals(federationLink)) {
            			UserFederationProviderFactory factory = (UserFederationProviderFactory)session.getKeycloakSessionFactory().getProviderFactory(UserFederationProvider.class, federation.getProviderName());

            			UserFederationProvider fed = factory.getInstance(session, federation);
            			if (fed.isValid(roleModel)) {
            				roles.add(ModelToRepresentation.toRepresentation(roleModel));
            			} else {
            				deleteRole(roleModel);
            			}
            			break;
            		}
            	}
        	}
        }
        return roles;
    }

    /**
     * Create a new role for this realm or application
     *
     * @param uriInfo
     * @param rep
     * @return
     */
    @POST
    @Consumes("application/json")
    public Response createRole(final @Context UriInfo uriInfo, final RoleRepresentation rep) {
        auth.requireManage();

        try {
            RoleModel role = roleContainer.addRole(rep.getName());
            
            role.setDescription(rep.getDescription());
            
            try {
            
            	for (UserFederationProviderModel federation : realm.getUserFederationProviders()) {
            		if (federation.supportRoles()) {
            			UserFederationProviderFactory factory = (UserFederationProviderFactory)session.getKeycloakSessionFactory().getProviderFactory(UserFederationProvider.class, federation.getProviderName());

            			UserFederationProvider fed = factory.getInstance(session, federation);
            			if (fed.synchronizeRegistrations()) {
            				fed.createRole(realm, role);
            				role.setFederationLink(federation.getId());
            				break;
            			}
            		}
            	}
            	
            	if (session.getTransaction().isActive()) {
            		session.getTransaction().commit();
                }
            } catch (ModelDuplicateException mde) {
            	if (session.getTransaction().isActive()) {
                    session.getTransaction().setRollbackOnly();
                }
            	return Flows.errors().exists("Role with name " + rep.getName() + " already exists in federated store.");
        	} catch (IllegalStateException ise) {
        		logger.warn("Failed to create role " + role.getName() + " in federated store.  Ignore the exception because either federation is read-only or syncing to federation is turned off in configuration.  Keycloak roles could get out of sync with groups in federated store though. " + ise);
        	}

            return Response.created(uriInfo.getAbsolutePathBuilder().path(role.getName()).build()).build();
        } catch (ModelDuplicateException e) {
        	if (session.getTransaction().isActive()) {
                session.getTransaction().setRollbackOnly();
            }
            return Flows.errors().exists("Role with name " + rep.getName() + " already exists in keycloak.");
        } catch (Exception e) {
        	if (session.getTransaction().isActive()) {
                session.getTransaction().setRollbackOnly();
            }
            return Flows.errors().exists("Role with name " + rep.getName() + " can not be added due to the following error: " + e.getCause().getMessage());
        }
    }

    /**
     * Get a role by name
     *
     * @param roleName role's name (not id!)
     * @return
     */
    @Path("{role-name}")
    @GET
    @NoCache
    @Produces("application/json")
    public RoleRepresentation getRole(final @PathParam("role-name") String roleName) {
        auth.requireView();

        RoleModel roleModel = roleContainer.getRole(roleName);
        if (roleModel == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        return getRole(roleModel);
    }

    /**
     * Delete a role by name
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}")
    @DELETE
    @NoCache
    public void deleteRole(final @PathParam("role-name") String roleName) {
        auth.requireManage();

        try {
        	RoleModel role = roleContainer.getRole(roleName);
        	if (role == null) {
        		throw new NotFoundException("Could not find role: " + roleName);
        	}
        	String federationLink = role.getFederationLink();
        	deleteRole(role);

        	if (federationLink != null) {
        		try {

        			for (UserFederationProviderModel federation : realm.getUserFederationProviders()) {
        				if (federation.getId().equals(federationLink)) {
        					UserFederationProviderFactory factory = (UserFederationProviderFactory)session.getKeycloakSessionFactory().getProviderFactory(UserFederationProvider.class, federation.getProviderName());

        					UserFederationProvider fed = factory.getInstance(session, federation);
        					if (fed.synchronizeRegistrations()) {
        						boolean done = fed.removeRole(realm, role);
        						if (!done) {
        							logger.warn("Failed to remove role " + role.getName() + " from federation.  This role may no longer exist in federated store.");
        						}
        					}
        					break;
        				}
        			}

        			if (session.getTransaction().isActive()) {
        				session.getTransaction().commit();
        			}
        		} catch (IllegalStateException ise) {
        			logger.warn("Failed to remove role " + role.getName() + " from federation.  Ignore the exception because either user federation is read-only or syncing to user federation is turned off in configuration.  Keycloak roles could get out of sync with groups in federated store though. " + ise);
        		} catch (ModelException me) {
        			logger.warn("Failed to remove role " + role.getName() + " from federation.  Ignore the exception because this role may no longer exist in federated store. " + me);
        		}
        	}
        } catch(Exception e) {
        	logger.error("Failed to delete role " + roleName + ": " + e);
        	if (session.getTransaction().isActive()) {
        		session.getTransaction().setRollbackOnly();
        	}
        }
    }

    /**
     * Update a role by name
     *
     * @param roleName role's name (not id!)
     * @param rep
     * @return
     */
    @Path("{role-name}")
    @PUT
    @Consumes("application/json")
    public Response updateRole(final @PathParam("role-name") String roleName, final RoleRepresentation rep) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        try {
            updateRole(rep, role);
            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return Flows.errors().exists("Role with name " + rep.getName() + " already exists");
        }
    }

    /**
     * Add a composite to this role
     *
     * @param roleName role's name (not id!)
     * @param roles
     */
    @Path("{role-name}/composites")
    @POST
    @Consumes("application/json")
    public void addComposites(final @PathParam("role-name") String roleName, List<RoleRepresentation> roles) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        addComposites(roles, role);
    }

    /**
     * List composites of this role
     *
     * @param roleName role's name (not id!)
     * @return
     */
    @Path("{role-name}/composites")
    @GET
    @NoCache
    @Produces("application/json")
    public Set<RoleRepresentation> getRoleComposites(final @PathParam("role-name") String roleName) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        return getRoleComposites(role);
    }

    /**
     * Get realm-level roles of this role's composite
     *
     * @param roleName role's name (not id!)
     * @return
     */
    @Path("{role-name}/composites/realm")
    @GET
    @NoCache
    @Produces("application/json")
    public Set<RoleRepresentation> getRealmRoleComposites(final @PathParam("role-name") String roleName) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        return getRealmRoleComposites(role);
    }

    /**
     * An app-level roles for a specific app for this role's composite
     *
     * @param roleName role's name (not id!)
     * @param appName
     * @return
     */
    @Path("{role-name}/composites/application/{app}")
    @GET
    @NoCache
    @Produces("application/json")
    public Set<RoleRepresentation> getApplicationRoleComposites(final @PathParam("role-name") String roleName,
                                                                final @PathParam("app") String appName) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        ApplicationModel app = realm.getApplicationByName(appName);
        if (app == null) {
            throw new NotFoundException("Could not find application: " + appName);

        }
        return getApplicationRoleComposites(app, role);
    }


    /**
     * An app-level roles for a specific app for this role's composite
     *
     * @param roleName role's name (not id!)
     * @param appId
     * @return
     */
    @Path("{role-name}/composites/application-by-id/{appId}")
    @GET
    @NoCache
    @Produces("application/json")
    public Set<RoleRepresentation> getApplicationByIdRoleComposites(final @PathParam("role-name") String roleName,
                                                                final @PathParam("appId") String appId) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        ApplicationModel app = realm.getApplicationById(appId);
        if (app == null) {
            throw new NotFoundException("Could not find application: " + appId);

        }
        return getApplicationRoleComposites(app, role);
    }


    /**
     * Remove roles from this role's composite
     *
     * @param roleName role's name (not id!)
     * @param roles roles to remove
     */
    @Path("{role-name}/composites")
    @DELETE
    @Consumes("application/json")
    public void deleteComposites(final @PathParam("role-name") String roleName, List<RoleRepresentation> roles) {
        auth.requireManage();

        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role: " + roleName);
        }
        deleteComposites(roles, role);
    }


}
