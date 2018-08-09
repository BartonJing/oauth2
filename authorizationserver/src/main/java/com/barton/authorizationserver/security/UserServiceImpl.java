package com.barton.authorizationserver.security;

import com.barton.authorizationserver.domian.AuthUser;
import com.barton.authorizationserver.domian.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;

/**
 * create by barton on 2018-7-2
 */
@Service
public class UserServiceImpl implements UserService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        //模拟存数据库等持久化存储中读取用户信息
        AuthUser authUser = new AuthUser();
        authUser = authUser.findUSer(s);
        if(authUser == null){
            throw new UsernameNotFoundException("未找到用户!");
        }
        return new UserRepositoryUserDetails(authUser);
    }

    /**
     *  注意该类的层次结构，继承了Member并实现了UserDetails接口，继承是为了使用Member的username和password信息
     */
    private final static class UserRepositoryUserDetails extends AuthUser implements UserDetails {
        private static final long serialVersionUID = 1L;
        private UserRepositoryUserDetails(AuthUser authUser) {
            super(authUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            Role role = new Role();
            return role.getRoles();
        }

        @Override
        public String getUsername() {
            return super.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

    }

}
