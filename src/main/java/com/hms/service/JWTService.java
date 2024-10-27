package com.hms.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
 import org.springframework.beans.factory.annotation.Value;

import java.util.Date;

@Service
public class JWTService {
   @ Value("${jwt.algorithm.key}")
    private String algorithmsKey;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.expiry.duration}")
    private int expiryTime;

    private Algorithm algorithm;

    @PostConstruct
    public void postConstruct(){
      algorithm=  Algorithm.HMAC256(algorithmsKey);
    }
    public String generateToken(String username){
        // Computer Engineer Is UnEmployee
      return   JWT.create()
                .withClaim("name",username)
                .withExpiresAt(new Date(System.currentTimeMillis()+expiryTime))
                .withIssuer(issuer)
                .sign(algorithm);
    }

    public String getUsername(String token){
        DecodedJWT decodeJWT = JWT.
                require(algorithm).
                withIssuer(issuer).
                build()
                .verify(token);
        return decodeJWT.getClaim("name").asString();


    }
}
