package com.barton.authorizationserver.domian;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.Serializable;

/**
 * create by barton on 2018-7-3
 */
public class AuthUser  implements Serializable {


    private String id;
    /**
     * 用户名称
     */
    private String username;
    /**
     * 密码
     */
    private String password;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public AuthUser(String username, String password) {
        this.username = username;
        this.password = password;
    }
    public AuthUser(AuthUser authUser) {
        this.username = authUser.getUsername();
        this.password = authUser.getPassword();
    }
    public AuthUser() {
    }

    /**
     * 模拟从数据库等持久化存储中取出对应的用户信息
     * @param username
     * @return
     */
    public AuthUser findUSer(String username){
        System.out.println("*****************   "+username);
        String finalSecret = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
        System.out.println(finalSecret);
        return new AuthUser("user_1",finalSecret);
    }
}
