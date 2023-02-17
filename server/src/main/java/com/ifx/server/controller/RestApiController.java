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

package com.ifx.server.controller;

import com.ifx.server.entity.User;
import com.ifx.server.model.*;
import com.ifx.server.model.stateful.Device;
import com.ifx.server.model.stateful.Whitelist;
import com.ifx.server.model.stateless.*;
import com.ifx.server.service.CoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.ifx.server.EndpointConstants.*;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
public class RestApiController {

    @Autowired
    private CoreService coreService;

    /**
     * Web Frontend Access
     */

    @GetMapping(STATEFUL_PING_URL)
    @PostMapping(STATEFUL_PING_URL)
    public Response<String> processPing() {
        return coreService.restPing();
    }

    @GetMapping(STATEFUL_GET_USERNAME_URL)
    public Response<String> processGetUsername() {
        return coreService.restGetUsername();
    }

    @PostMapping(STATEFUL_SIGN_UP_URL)
    public Response<String> processRegistration(@RequestBody User userForm, BindingResult bindingResult) {
        return coreService.restUserRegistration(userForm, bindingResult);
    }

    @GetMapping(STATEFUL_SIGN_OUT_URL)
    public Response<String> processLogout(HttpServletRequest request) {
        return coreService.restUserSignOut(request);
    }

    @RequestMapping(value = STATEFUL_ERROR_URL, method = GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public Response<Object> processError(HttpServletResponse response) {
        return coreService.restError(response);
    }

    @PostMapping(STATEFUL_DEREGISTER_URL)
    public Response<String> processDeregister1(@RequestBody Device device, HttpServletResponse servletResponse) {
        return coreService.restDeregister1(device, servletResponse);
    }

    @GetMapping(STATEFUL_FACTORY_RESET)
    public Response<String> processFactoryReset() {
        return coreService.restFactoryReset();
    }

    @PostMapping(STATEFUL_WHITELIST_ACTIVATION_URL)
    public Response<String> processWhitelistActivation(@RequestBody Whitelist whitelist, HttpServletResponse servletResponse) {
        return coreService.restWhitelistActivation(whitelist, servletResponse);
    }

    @PostMapping(STATEFUL_WHITELIST_UPLOAD_URL)
    public Response<String> processWhitelistUpload(@RequestBody Whitelist whitelist, HttpServletResponse servletResponse) {
        return coreService.restWhitelistUpload(whitelist, servletResponse);
    }

    @PostMapping(STATEFUL_WHITELIST_REMOVE_URL)
    public Response<String> processWhitelistRemove(@RequestBody Whitelist whitelist, HttpServletResponse servletResponse) {
        return coreService.restWhitelistDelete(whitelist, servletResponse);
    }

    /**
     * Device Access
     */

    @PostMapping(STATELESS_SIGN_UP_URL)
    public Response<OnBoardResp> processOnBoard(@RequestBody OnBoard onBoard, HttpServletResponse servletResponse) {
        return coreService.restOnBoard(onBoard, servletResponse);
    }

    @PostMapping(STATELESS_SIGN_UP_ACK_URL)
    public Response<OnBoardAckResp> processOnBoardAck(@RequestBody OnBoardAck onBoardAck, HttpServletResponse servletResponse) {
        return coreService.restOnBoardAck(onBoardAck, servletResponse);
    }

    @PostMapping(STATELESS_GET_CHALLENGE_URL)
    public Response<ChallengeResp> processGetChallenge(@RequestBody Challenge challenge, HttpServletResponse servletResponse) {
        return coreService.restGetChallenge(challenge, servletResponse);
    }

    @PostMapping(STATELESS_KEY_EXCHANGE_URL)
    public Response<KeyExchangeResp> processKeyExchange(@RequestBody KeyExchange keyExchange, HttpServletResponse servletResponse) {
        return coreService.restKeyExchange(keyExchange, servletResponse);
    }

    @PostMapping(STATELESS_DOWNLOAD_URL)
    public ResponseEntity<Resource> processDownload(@RequestBody Download download) {
        return coreService.restDownload(download);
    }

    @GetMapping(STATELESS_DEREGISTER_URL)
    public Response<String> processDeregister2(HttpServletResponse servletResponse) {
        return coreService.restDeregister2(servletResponse);
    }
}
