package com.hms.controller;

import com.hms.entity.AppUser;
import com.hms.payload.LoginDto;
import com.hms.payload.TokenDto;
import com.hms.repository.AppUserRepository;
import com.hms.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/users")

public class UserController {
    private AppUserRepository appUserRepository;
    private UserService userService;


    public UserController(AppUserRepository appUserRepository, UserService userService) {
        this.appUserRepository = appUserRepository;
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> createUser(
            @RequestBody AppUser user
    ) {
        Optional<AppUser> opUserName = appUserRepository.findByUsername(user.getUsername());

        if (opUserName.isPresent()) {
            return new ResponseEntity<>("username already taken", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        Optional<AppUser> opEmail = appUserRepository.findByEmail(user.getEmail());

        if (opEmail.isPresent()) {
            return new ResponseEntity<>("Email already taken", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        // encrypt the password
        String encryptedPassword = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt(5));
        user.setPassword(encryptedPassword);
        //this is standard way  for define the role of the user
        // Q) how did u work on building multiple signupwith with different roles
        user.setRole("ROLE_USER");
        AppUser savedUser = appUserRepository.save(user);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);


    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto dto) {
        String token = userService.verifyLogin(dto);
        if (token != null) {
            TokenDto tokenDto = new TokenDto();
            tokenDto.setToken(token);
            tokenDto.setType("JWT");
            return new ResponseEntity<>(tokenDto, HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Invalid username/passsword", HttpStatus.FORBIDDEN);
        }
    }

    @PostMapping("/signup-property-owner")
    public ResponseEntity<?> createPropertyOwnerUser(
            @RequestBody AppUser user
    ) {
        Optional<AppUser> opUserName = appUserRepository.findByUsername(user.getUsername());

        if (opUserName.isPresent()) {
            return new ResponseEntity<>("username already taken", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        Optional<AppUser> opEmail = appUserRepository.findByEmail(user.getEmail());

        if (opEmail.isPresent()) {
            return new ResponseEntity<>("Email already taken", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        // encrypt the password
        String encryptedPassword = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt(5));
        user.setPassword(encryptedPassword);
        //this is standard way  for define the role of the user
        // Q) how did u work on building multiple signupwith with different roles
        user.setRole("ROLE_OWNER");
        AppUser savedUser = appUserRepository.save(user);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);


    }

}
