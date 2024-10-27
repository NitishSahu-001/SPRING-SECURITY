package com.hms;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class A {
    public static void main(String[] args) {
//        PasswordEncoder  en=new BCryptPasswordEncoder();
//        System.out.println(en.encode("testing"));
        String enPwd = BCrypt.hashpw("testing", BCrypt.gensalt(5));

        System.out.println(enPwd);
    }
}
