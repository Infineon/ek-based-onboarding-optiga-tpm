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

package com.ifx.server.config;

import com.ifx.server.repository.DeviceRepositoryService;
import com.ifx.server.service.security.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static com.ifx.server.EndpointConstants.*;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Handle stateless request using JWT as authentication method
     * e.g. device access
     */
    @Configuration
    @Order(1)
    public class StatelessecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        private DeviceRepositoryService deviceRepositoryService;
        @Autowired
        private SimpMessagingTemplate simpMessagingTemplate;

        @Override
        protected void configure(final HttpSecurity http) throws Exception {
            // Security configuration for all endpoints, comprises REST services and websockets
            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .antMatcher(STATELESS_ALL_URLS)
                    .authorizeRequests()
                    .antMatchers(STATELESS_SIGN_UP_URL, STATELESS_SIGN_UP_ACK_URL, STATELESS_GET_CHALLENGE_URL, STATELESS_SIGN_IN_URL).permitAll()
                    .antMatchers(STATELESS_KEY_EXCHANGE_URL, STATELESS_DEREGISTER_URL, STATELESS_DOWNLOAD_URL).hasRole("DEVICE")
                    .anyRequest().authenticated()
                .and()
                    .antMatcher(STATELESS_ALL_URLS)
                    /**
                     * Set SSL requirement for all channels
                     */
                    .requiresChannel()
                    .anyRequest().requiresSecure()
                .and()
                    .antMatcher(STATELESS_ALL_URLS)
                    .exceptionHandling().accessDeniedPage(STATEFUL_HOME_URL)
                .and()
                    .antMatcher(STATELESS_ALL_URLS)
                    .requestCache().disable()
                    /**
                     * Disable the requirement of X-CSRF-TOKEN in header for endpoints.
                     * This will affect POST only, csrf does not affect GET and permitAll()
                     */
                    .csrf().disable();
            /**
             * custom filters
             */
            http.antMatcher(STATELESS_ALL_URLS)
                    .addFilter(new JWTAuthenticationFilter(authenticationManager(), deviceRepositoryService, simpMessagingTemplate))
                    .addFilter(new JWTAuthorizationFilter(authenticationManager(), deviceRepositoryService, simpMessagingTemplate));
        }

    }

    /**
     * Handle stateful request using cookie with JSESSIONID as authentication method
     * e.g. web page access
     */
    @Configuration
    @Order(2)
    public class StatefulSecurityConfig extends WebSecurityConfigurerAdapter {

        @Qualifier("userInformationService")
        @Autowired
        private UserDetailsService userDetailsService;

        @Override
        public void configure(AuthenticationManagerBuilder builder)
                throws Exception {
            builder.userDetailsService(userDetailsService);
        }

        @Override
        protected void configure(final HttpSecurity http) throws Exception {
            // Security configuration for all endpoints, comprises REST services and websockets
            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                    .csrf()
                    /**
                     * Disable the requirement of X-CSRF-TOKEN in header for endpoints.
                     * This will affect POST only, csrf does not affect GET and permitAll()
                     */
                    //.ignoringAntMatchers()
                .and()
                    .authorizeRequests()
                    .antMatchers(STATEFUL_ROOT_URL, STATEFUL_HOME_URL, STATEFUL_ALL_STATIC_URLS, STATEFUL_ALL_WEBJAR_URLS,
                            STATEFUL_ENTRY_URL, STATEFUL_SIGN_UP_URL, STATEFUL_SIGN_IN_URL, STATEFUL_PING_URL,
                            STATEFUL_ERROR_URL, STATEFUL_FACTORY_RESET).permitAll()
                    .antMatchers(STATEFUL_DASHBOARD_URL, STATEFUL_GET_USERNAME_URL, STATEFUL_SIGN_OUT_URL,
                            STATEFUL_DEREGISTER_URL, STATEFUL_WEBSOCKET_URL,
                            STATEFUL_WHITELIST_UPLOAD_URL, STATEFUL_WHITELIST_REMOVE_URL,
                            STATEFUL_WHITELIST_ACTIVATION_URL).hasRole("USER")
                    .anyRequest().authenticated()
                .and()
                    /**
                     * Set SSL requirement for all channels
                     */
                    .requiresChannel()
                    .anyRequest().requiresSecure()
                .and()
                    .exceptionHandling().accessDeniedPage(STATEFUL_HOME_URL)
                .and()
                    .requestCache().disable();

            /**
             * custom filters
             */
            http.addFilter(new StatefulAuthenticationFilter(authenticationManager(), userDetailsService));

        }

        @Bean
        public AuthenticationManager customAuthenticationManager() throws Exception {
            return authenticationManager();
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring()
                    .antMatchers("/h2-console/**");
        }
    }
}
