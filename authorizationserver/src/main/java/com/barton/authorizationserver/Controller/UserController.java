package com.barton.authorizationserver.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * create by barton on 2018-7-2
 */
@RestController
public class UserController {

    @Autowired
    private TokenStore tokenStore;
    @PostMapping("/bar")
    public String bar(@RequestHeader("Authorization") String auth) {

        User userDetails = (User) tokenStore.readAuthentication(auth.split(" ")[1]).getPrincipal();

        //User user = userDetails.getUser();

        return userDetails.getUsername() + ":" + userDetails.getPassword();
    }
}
