package com.barton.authorizationserver.domian;

import org.springframework.security.core.GrantedAuthority;

import java.util.HashSet;
import java.util.Set;

/**
 * create by barton on 2018-7-3
 */
public class Role implements GrantedAuthority {

    private static final long serialVersionUID = -2633659220734280260L;

    private Set<Role> roles = new HashSet<Role>();

    @Override
    public String getAuthority() {
        return "USER";
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
