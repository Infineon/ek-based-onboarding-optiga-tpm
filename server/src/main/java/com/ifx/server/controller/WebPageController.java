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

import com.ifx.server.service.CoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import static com.ifx.server.EndpointConstants.*;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
public class WebPageController {

    @Autowired
    private CoreService coreService;

    @GetMapping({STATEFUL_ROOT_URL, STATEFUL_HOME_URL})
    public String home(Model model) {
        return coreService.viewHome(model);
    }

    @GetMapping(STATEFUL_ENTRY_URL)
    public String sendRegistration(Model model) {
        return coreService.viewEntry(model);
    }

    @GetMapping(STATEFUL_DASHBOARD_URL)
    public String sendDashboard(Model model) {
        return coreService.viewDashboard(model);
    }

    @RequestMapping(value = STATEFUL_ERROR_URL, method = GET, produces = MediaType.TEXT_HTML_VALUE)
    public String processError(Model model) {
        return coreService.viewHome(model);
    }
}
