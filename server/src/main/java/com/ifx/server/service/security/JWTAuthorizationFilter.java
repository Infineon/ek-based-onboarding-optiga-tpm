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
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.ifx.server.entity.Device;
import com.ifx.server.entity.Role;
import com.ifx.server.model.Response;
import com.ifx.server.model.stateful.Console;
import com.ifx.server.repository.DeviceRepositoryService;
import org.springframework.http.MediaType;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static com.ifx.server.service.security.SecurityConstants.HEADER_STRING;
import static com.ifx.server.service.security.SecurityConstants.TOKEN_PREFIX;
import static com.ifx.server.service.security.SecurityConstants.SECRET;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private DeviceRepositoryService deviceRepositoryService;
    private SimpMessagingTemplate simpMessagingTemplate;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, DeviceRepositoryService deviceRepositoryService,
                                  SimpMessagingTemplate simpMessagingTemplate) {
        super(authenticationManager);
        this.deviceRepositoryService = deviceRepositoryService;
        this.simpMessagingTemplate = simpMessagingTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        try {
            String header = req.getHeader(HEADER_STRING);

            if (header == null || !header.startsWith(TOKEN_PREFIX)) {
                // no JWT available for authentication
            } else {
                UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
                if (authentication != null)
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                else
                    throw new Exception("Bad JWT");
            }

            chain.doFilter(req, res);

        } catch (Exception e) {
            Gson gson = new Gson();
            Response<String> resp = new Response<String>(Response.STATUS_ERROR, e.getMessage(), null);
            String respJsonString = gson.toJson(resp);
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.setCharacterEncoding("UTF-8");
            res.getWriter().print(respJsonString);
            res.getWriter().flush();
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) throws Exception {
        String token = request.getHeader(HEADER_STRING);

        // parse the token.
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
                .build()
                .verify(token.replace(TOKEN_PREFIX, ""));
        String name = decodedJWT.getSubject();
        Date expiry = decodedJWT.getExpiresAt();
        long expiry_mins = ChronoUnit.MINUTES.between(
                    ZonedDateTime.now(),
                    ZonedDateTime.ofInstant(
                        expiry.toInstant(), ZoneId.of("UTC")
                ));

        if (name != null) {
            Device device = deviceRepositoryService.findByDeviceName(name);
            log(device.getGid(),
                    "\n=========================================\n" +
                        "JWT verified ok\n" +
                        "JWT subject: " + name + "\n" +
                        "JWT expire in: " + expiry_mins + " mins"
            );
            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
            for (Role role : device.getRoles()){
                grantedAuthorities.add(new SimpleGrantedAuthority(role.getName()));
            }
            return new UsernamePasswordAuthenticationToken(device.getName(), "", grantedAuthorities);
        }

        return null;
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
