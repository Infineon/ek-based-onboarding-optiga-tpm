/**
 * MIT License
 *
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

package com.ifx.server.service.security;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.ifx.server.entity.Device;
import com.ifx.server.entity.Role;
import com.ifx.server.model.Response;
import com.ifx.server.model.stateful.Console;
import com.ifx.server.model.stateless.AuthJWT;
import com.ifx.server.repository.DeviceRepositoryService;
import com.ifx.server.tss.DuplicateECC;
import com.ifx.server.tss.DuplicateHMAC;
import com.ifx.server.tss.DuplicateRSA;
import org.springframework.http.MediaType;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.ifx.server.EndpointConstants.STATELESS_SIGN_IN_URL;
import static com.ifx.server.service.security.SecurityConstants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    private DeviceRepositoryService deviceRepositoryService;
    private SimpMessagingTemplate simpMessagingTemplate;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, DeviceRepositoryService deviceRepositoryService,
                                   SimpMessagingTemplate simpMessagingTemplate) {
        this.authenticationManager = authenticationManager;
        this.deviceRepositoryService = deviceRepositoryService;
        this.simpMessagingTemplate = simpMessagingTemplate;
        this.setFilterProcessesUrl(STATELESS_SIGN_IN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        String username = "";
        try {
            AuthJWT auth = new ObjectMapper()
                    .readValue(req.getInputStream(), AuthJWT.class);

            String name = auth.getId();
            Device device = deviceRepositoryService.findByDeviceName(name);

            if (device == null || device.getState() != Device.STATE_ACTIVE)
                throw new MyAuthenticationException("device not registered");

            String challenge = device.getChallenge();
            if (challenge == "" || challenge == null)
                throw new MyAuthenticationException("unable to retrieve challenge");

            username = device.getGid();
            log(username,
                    "\n=========================================\n" +
                            "Server received authentication request\n" +
                            "=========================================\n");

            // Verify HMAC
            DuplicateHMAC hmac = new DuplicateHMAC();
            hmac.importPub(device.getHmacPub());
            hmac.importPriv(device.getHmacPriv());
            hmac.rxConvoySignature(challenge, auth.getSigHmac());
            if (!hmac.verify())
                throw new MyAuthenticationException("Authentication failed: bad HMAC-based signature");
            log(username, "HMAC-based signature verified ok\n");

            // Verify RSA
            DuplicateRSA rsa = new DuplicateRSA();
            rsa.importPub(device.getRsa());
            rsa.rxConvoySignature(challenge, auth.getSigRsa());
            if (!rsa.verify())
                throw new MyAuthenticationException("Authentication failed: bad RSA-based signature");
            log(username, "RSA-based signature verified ok\n");

            // Verify ECC
            DuplicateECC ecc = new DuplicateECC();
            ecc.importPub(device.getEcc());
            ecc.rxConvoySignature(challenge, auth.getSigEcc());
            if (!ecc.verify())
                throw new MyAuthenticationException("Authentication failed: bad ECC-based signature");
            log(username, "ECC-based signature verified ok\n");

            // Invalidate challenge
            device.setChallenge("");
            deviceRepositoryService.save(device);

            // Return authenticated token
            log(username, "Generate JWT (RFC 7519), place it in http authorization header\n");
            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
            for (Role role : device.getRoles()){
                grantedAuthorities.add(new SimpleGrantedAuthority(role.getName()));
            }
            return new UsernamePasswordAuthenticationToken(device.getName(), "", grantedAuthorities);
        } catch (MyAuthenticationException e) {
            try {
                log(username, "Failed with error: " + e.toString() + "\n");

                Gson gson = new Gson();
                Response<String> resp = new Response<String>(Response.STATUS_ERROR, e.getMessage(), null);
                String respJsonString = gson.toJson(resp);
                res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                res.setContentType(MediaType.APPLICATION_JSON_VALUE);
                res.setCharacterEncoding("UTF-8");
                res.getWriter().print(respJsonString);
                res.getWriter().flush();

                return null;
            } catch (Exception e1) {
                throw new RuntimeException(e1);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        if (auth.isAuthenticated()) {
            String user = (String) auth.getPrincipal();
            String token = JWT.create()
                    .withSubject(user)
                    .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .sign(HMAC512(SECRET.getBytes()));
            res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
        }
    }

    public class MyAuthenticationException extends Exception {
        public MyAuthenticationException(String errorMessage) {
            super(errorMessage);
        }
    }

    private void log(String username, String m) {
        try {
            if (username != null && username != "")
                simpMessagingTemplate.convertAndSendToUser(username, "/topic/private",
                        new Response<Console>(Response.STATUS_OK, new Console(m)));
        } catch (Exception e) {

        }
    }
}
