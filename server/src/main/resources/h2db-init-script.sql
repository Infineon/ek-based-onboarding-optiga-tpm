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

INSERT INTO role (name) VALUES
  ('ROLE_ADMIN'),
  ('ROLE_GUEST'),
  ('ROLE_USER'),
  ('ROLE_DEVICE');

INSERT INTO user (username, password, whitelistisactivated) VALUES
  ('admin', '$2a$10$XhD5CAjcl5CqQ3oWYBtMQ.IhhGBUVWvC4ZrYZqdpb9r2D9d8NVHLW', false), /* password: nimda */
  ('infineon', '$2a$10$gFGZR4PbZrNg1jqNsb1XT.eUZXyaVxUkzlmCRZcS2swjBmdyXxtva', false); /* password: noenifni */

INSERT INTO user_roles (users_id, roles_id) VALUES
  ('1', '1'),
  ('1', '2'),
  ('1', '3'),
  ('2', '3');

