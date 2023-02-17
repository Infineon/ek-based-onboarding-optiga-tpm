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

import com.ifx.server.entity.User;
import com.ifx.server.repository.UserRepositoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;

/**
 * Required by Spring Security engine
 * This class is to perform user authentication/verification
 */
@Component
public class UserValidator {
    @Autowired
    private UserRepositoryService userRepoService;

    public void validate(Object o, Errors errors) {
        User user = (User) o;

        if (userRepoService.count() > 100) {
            // prevent DoS attack
            errors.rejectValue("username", "exceeded.max.reg.user");
        }

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "username", "NotEmpty");
        /*if (user.getUsername().length() < 6 || user.getUsername().length() > 32) {
            errors.rejectValue("username", "Size.userForm.username");
        }*/
        if (userRepoService.findByUsername(user.getUsername()) != null) {
            errors.rejectValue("username", "Duplicate.userForm.username");
        }

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "password", "NotEmpty");
        /*if (user.getPassword().length() < 8 || user.getPassword().length() > 32) {
            errors.rejectValue("password", "Size.userForm.password");
        }*/

        if (!user.getPasswordConfirm().equals(user.getPassword())) {
            errors.rejectValue("passwordConfirm", "Diff.userForm.passwordConfirm");
        }
    }
}
