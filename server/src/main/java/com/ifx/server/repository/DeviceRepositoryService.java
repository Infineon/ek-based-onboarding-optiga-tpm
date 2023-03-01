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

package com.ifx.server.repository;

import com.ifx.server.entity.Device;
import com.ifx.server.entity.Role;
import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class is to store user registration info into database
 */
@Service
public class DeviceRepositoryService {
    @Autowired
    private DeviceRepository deviceRepository;
    @Autowired
    private RoleRepository roleRepository;

    public void create(Device device) {
        device = setDefaultRole(device);
        deviceRepository.save(device);
    }

    public void save(Device device) {
        deviceRepository.save(device);
    }

    private Device setDefaultRole(Device device) {
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(Role.ROLE_DEVICE));
        device.setRoles(roles);
        return device;
    }

    @Transactional(readOnly = true)
    public Device findByDeviceName(String name) {
        Device d = deviceRepository.findByName(name);
        if (d != null)
            Hibernate.initialize(d.getRoles()); // to fix hibernate:lazyinitializationexception cause by filter access database
        return d;
    }

    @Transactional(readOnly = true)
    public Device findByDeviceEk(String ek) {
        Device d = deviceRepository.findByEk(ek);
        if (d != null)
            Hibernate.initialize(d.getRoles()); // to fix hibernate:lazyinitializationexception cause by filter access database
        return d;
    }

    /**
     * Warning: Device's roles are not initialized, reading it will
     * trigger lazyinitializationexception
     * @param username
     * @return
     */
    @Transactional(readOnly = true)
    public List<Device> findAllByUsername(String username) {
        List<Device> d = deviceRepository.findAllByGid(username);

        /* if device roles are needed, implement Hibernate.initialize(d.getRoles()) */

        return d;
    }
}
