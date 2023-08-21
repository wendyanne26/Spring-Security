package com.example.demo.securityUtils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Objects;

public class SecurityUtils {
    public UserDetails getCurrentUserDetails(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(Objects.isNull(authentication)){
            return null;
        }
        Object principal = authentication.getPrincipal();
        if(!Objects.isNull(principal)){
            return (UserDetails) principal;
        }
        return null;
    }
}
