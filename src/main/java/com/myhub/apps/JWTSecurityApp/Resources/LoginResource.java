package com.myhub.apps.JWTSecurityApp.Resources;

import com.myhub.apps.JWTSecurityApp.model.AuthenticationRequest;
import com.myhub.apps.JWTSecurityApp.model.AutheticationResponse;
import com.myhub.apps.JWTSecurityApp.services.MyUserDetailsService;
import com.myhub.apps.JWTSecurityApp.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class LoginResource {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JWTUtil jwtUtil;

    @RequestMapping(value="/authenticate",method = RequestMethod.POST)
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword())
            );

        }catch (Exception e){
            throw  new Exception("Bad credentials",e);
        }

        final UserDetails userDetails=userDetailsService.loadUserByUsername(authenticationRequest.getUserName());
        final String token =jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AutheticationResponse(token));
    }

    @GetMapping("/hello")
    public String hello(){
        return "<h3>Hello User, Warm Welcome to you !</h3>";
    }



}
