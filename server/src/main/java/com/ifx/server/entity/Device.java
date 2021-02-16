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

package com.ifx.server.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "device") // automate creation of table 'role'
@Getter
@Setter
public class Device {
    @Transient
    public static final int STATE_PENDING = 0x02034762;
    @Transient
    public static final int STATE_ACTIVE = 0x08153648;
    @Transient
    public static final int STATE_DEAD = 0x05623952;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Getter(onMethod_=@JsonIgnore) // ignore this field during Jackson serialization
    private Long id;

    @Getter(onMethod_=@JsonIgnore) // ignore this field to prevent infinite recursive during Jackson serialization of User.class
    @ManyToMany(mappedBy = "devices")
    private Set<User> users;

    // notice this will create an additional table in database to help to relate entities
    // of 2 tables with each other in both direction Role<->Device
    @ManyToMany
    // @JoinTable is not necessary unless you are not happy with the default naming
    @JoinTable(
            name = "device_roles",
            joinColumns = @JoinColumn(name = "devices_id"),
            inverseJoinColumns = @JoinColumn(name = "roles_id"))
    private Set<Role> roles;

    private String gid;
    private String name;
    @Column(length = 3000)
    private String ek;
    @Column(length = 600)
    private String challenge;
    @Column(length = 3000)
    private String hmacPriv;
    @Column(length = 3000)
    private String hmacPub;
    @Column(length = 3000)
    private String rsa;
    @Column(length = 3000)
    private String ecc;
    @Column(length = 600)
    private String sharedKey;
    private int state;
}
