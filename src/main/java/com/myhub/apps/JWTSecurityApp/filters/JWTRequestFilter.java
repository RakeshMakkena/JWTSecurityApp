package com.myhub.apps.JWTSecurityApp.filters;

import com.myhub.apps.JWTSecurityApp.services.MyUserDetailsService;
import com.myhub.apps.JWTSecurityApp.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JWTUtil util;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader=request.getHeader("Authorization");

        String userName=null;
        String jwt=null;

        if(null !=authHeader && authHeader.startsWith("Bearer ")){
            jwt=authHeader.substring(7);
            userName=util.extractUsername(jwt);
        }

        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails=userDetailsService.loadUserByUsername(userName);

            if(util.validateToken(jwt,userDetails)){
                UsernamePasswordAuthenticationToken token =new UsernamePasswordAuthenticationToken(
                        userDetails,null,userDetails.getAuthorities()
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(token);
            }

        }

        filterChain.doFilter(request,response);

    }
}
