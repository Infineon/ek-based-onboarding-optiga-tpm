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

package com.ifx.server;

public class EndpointConstants {
    private static final String STATELESS_SUBDOMAIN = "/api";

    public static final String STATELESS_ALL_URLS = STATELESS_SUBDOMAIN + "/**";
    public static final String STATELESS_SIGN_UP_URL = STATELESS_SUBDOMAIN + "/onboard";
    public static final String STATELESS_SIGN_UP_ACK_URL = STATELESS_SUBDOMAIN + "/onboard-ack";
    public static final String STATELESS_GET_CHALLENGE_URL = STATELESS_SUBDOMAIN + "/get-challenge";
    public static final String STATELESS_SIGN_IN_URL = STATELESS_SUBDOMAIN + "/get-jwt";
    public static final String STATELESS_KEY_EXCHANGE_URL = STATELESS_SUBDOMAIN + "/key-exchange";
    public static final String STATELESS_DOWNLOAD_URL = STATELESS_SUBDOMAIN + "/download";
    public static final String STATELESS_DEREGISTER_URL = STATELESS_SUBDOMAIN + "/deregister";

    public static final String STATEFUL_ALL_STATIC_URLS = "/static/**";
    public static final String STATEFUL_ALL_WEBJAR_URLS = "/webjars/**";
    public static final String STATEFUL_ROOT_URL = "/";
    public static final String STATEFUL_HOME_URL = "/home";
    public static final String STATEFUL_ENTRY_URL = "/entry";
    public static final String STATEFUL_DASHBOARD_URL = "/dashboard";
    public static final String STATEFUL_ERROR_URL = "/error";

    public static final String STATEFUL_WEBSOCKET_URL = "/websocket";
    public static final String STATEFUL_SIGN_UP_URL = "/signup";
    public static final String STATEFUL_SIGN_IN_URL = "/signin";
    public static final String STATEFUL_PING_URL = "/ping";
    public static final String STATEFUL_GET_USERNAME_URL = "/get-username";
    public static final String STATEFUL_SIGN_OUT_URL = "/signout";
    public static final String STATEFUL_DEREGISTER_URL = "/deregister";
    public static final String STATEFUL_WHITELIST_ACTIVATION_URL = "/wl-act";
    public static final String STATEFUL_WHITELIST_UPLOAD_URL = "/wl-upload";
    public static final String STATEFUL_WHITELIST_REMOVE_URL = "/wl-remove";
    public static final String STATEFUL_FACTORY_RESET = "/rhbn67v49bna3wv78fw65fcdiyhbn6jmpcb764v";
}

