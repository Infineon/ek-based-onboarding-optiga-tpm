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

package com.ifx.server.service;

import com.ifx.server.entity.Device;
import com.ifx.server.entity.User;
import com.ifx.server.model.*;
import com.ifx.server.model.stateful.*;
import com.ifx.server.model.stateless.*;
import com.ifx.server.repository.*;
import com.ifx.server.service.security.UserValidator;
import com.ifx.server.tss.*;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestBody;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.security.AlgorithmParameters;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Service
public class CoreService {

    @Value("classpath:media/beach.3gp")
    private Resource resourceVideoBeach;
    @Value("classpath:media/plain.txt")
    private Resource resourceTextPlain;

    @Autowired
    private CertificationAuthority caManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserRepositoryService userRepoService;
    @Autowired
    private DeviceRepository deviceRepository;
    @Autowired
    private DeviceRepositoryService deviceRepoService;
    @Autowired
    private WhitelistRepository whitelistRepository;
    @Autowired
    private UserValidator userValidator;
    @Autowired
    private SimpMessagingTemplate simpMessagingTemplate;
    @Autowired
    @Qualifier("springSecurityFilterChain")
    private Filter springSecurityFilterChain;

    public CoreService() {
    }

    private String viewAddModelAttributeUsername(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof AnonymousAuthenticationToken == false) {
            model.addAttribute("username", " " + authentication.getName() + " | Log me out");
            return authentication.getName();
        }
        return null;
    }

    public String viewHome(Model model) {
        viewAddModelAttributeUsername(model);
        return "home";
    }

    public String viewEntry(Model model) {
        viewAddModelAttributeUsername(model);
        model.addAttribute("userCount", userRepository.count());
        return "entry";
    }

    public String viewDashboard(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        List<com.ifx.server.entity.Whitelist> whitelist = whitelistRepository.findAllByUsername(username);
        List<Device> devices = deviceRepoService.findAllByUsername(username);

        devices.removeIf(device -> device.getState() != Device.STATE_ACTIVE);

        model.addAttribute("user", userRepository.findByUsername(username));
        model.addAttribute("users", userRepository.findAll());
        model.addAttribute("devices", devices);
        model.addAttribute("whitelist", whitelist);
        viewAddModelAttributeUsername(model);
        return "dashboard";
    }

    public Response<String> restPing() {
        getSecurityFilterChain();
        return new Response<String>(Response.STATUS_OK, "Hello Client");
    }

    public Response<String> restGetUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return new Response<String>(Response.STATUS_OK, authentication.getName());
    }

    public Response<String> restUserRegistration(User userForm, BindingResult bindingResult) {
        userValidator.validate(userForm, bindingResult);

        if (bindingResult.hasErrors()) {
            if (bindingResult.toString().contains("exceeded.max.reg.user"))
                return new Response<String>(Response.STATUS_ERROR, "exceeded maximum user registration, please contact server admin");
            return new Response<String>(Response.STATUS_ERROR, null);
        }

        userRepoService.save(userForm);

        return new Response<String>(Response.STATUS_OK, null);
    }

    public Response<String> restUserSignOut(HttpServletRequest request) {
        try {
            SecurityContextHolder.clearContext();
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            return new Response<String>(Response.STATUS_OK, null);
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, null);
        }
    }

    public Response<Object> restError(HttpServletResponse response) {
        return new Response<Object>(Response.STATUS_OK, Integer.toString(response.getStatus()), null);
    }

    public Response<String> restDeregister1(com.ifx.server.model.stateful.Device device, HttpServletResponse servletResponse) {
        String username = "";
        String deviceName = " ";
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            username = authentication.getName();
            deviceName = device.getName();

            log(username,
                    "\n=========================================\n" +
                            "Server received device unpairing request\n" +
                            "=========================================\n");

            Device dev = deviceRepoService.findByDeviceName(deviceName);
            if (dev == null || !dev.getGid().equals(username))
                throw new Exception("Device \"" + deviceName + "\" is not paired to user \"" + username + "\"");

            deviceRepository.deleteByName(deviceName);
            log(username, "Device \"" + deviceName + "\" is now unpaired\n");

            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<>(Response.STATUS_OK, null, null);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<String> restFactoryReset() {
        try{
            userRepository.deleteAll();
            deviceRepository.deleteAll();
            return new Response<String>(Response.STATUS_OK, null);
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, null);
        }
    }

    public Response<String> restWhitelistActivation(Whitelist whitelist, HttpServletResponse servletResponse) {

        String username = null;

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            username = authentication.getName();

            log(username,
                    "\n=========================================\n" +
                            "Server received request to activate/deactivate whitelist\n" +
                            "=========================================\n");

            User user = userRepository.findByUsername(username);
            if (whitelist.isActivated()) {
                log(username, "Whitelist is enabled\n");
                user.setWhitelistisactivated(true);
            } else {
                log(username, "Whitelist is disabled\n");
                user.setWhitelistisactivated(false);
            }
            userRepository.save(user);

            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<>(Response.STATUS_OK, null, null);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString());
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<String> restWhitelistUpload(Whitelist whitelist, HttpServletResponse servletResponse) {

        String username = null;

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            username = authentication.getName();

            log(username,
                    "\n=========================================\n" +
                            "Server received list of whitelisted devices\n" +
                            "=========================================\n");

            String csv = whitelist.getCsv();

            // 1st round of sanity check
            if (csv.contains(";"))
                throw new Exception("Should not contain ';'");
            if (csv.contains(","))
                throw new Exception("Should not contain ','");
            if (csv.contains(" "))
                throw new Exception("Should not contain empty space");
            if (csv.contains("0x"))
                throw new Exception("Should not contain '0x'");

            String list[] = csv.split("\\r?\\n");

            // 2nd round of sanity check
            if (list == null || list.length <= 0)
                throw new Exception("Empty list");
            if (list[0].length() != 512 && list[0].length() != 64) // EK RSA pubkey is 256bytes long; EK ECC P-256 pubkey is 32bytes long
                throw new Exception("Invalid public key length");

            String finalUsername = username;
            //Arrays.stream(device).parallel().forEach(entity -> {
            for (String entity : list) {
                // Need optimization here to avoid multiple database queries
                com.ifx.server.entity.Whitelist wl = whitelistRepository.findByUsernameAndPk(finalUsername, entity);
                if (wl == null) {
                    com.ifx.server.entity.Whitelist obj = new com.ifx.server.entity.Whitelist(finalUsername, entity);
                    whitelistRepository.save(obj);
                    log(username, "Public key: \"" + entity + "\" is now added to the whitelist\n");
                    // Update frontend whitelist table
                    simpMessagingTemplate.convertAndSendToUser(finalUsername, "/topic/private",
                            new Response<WhitelistInfo>(Response.STATUS_OK, new WhitelistInfo(obj)));
                }
            }
            //});

            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<>(Response.STATUS_OK, null, null);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() +
                    ". Possibly invalid file format, please upload csv formatted file only\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<String> restWhitelistDelete(Whitelist whitelist, HttpServletResponse servletResponse) {

        String username = null;

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            username = authentication.getName();

            log(username,
                    "\n=========================================\n" +
                            "Server received request to alter the whitelist\n" +
                            "=========================================\n");

            String pk = whitelist.getPk();
            // Sanity check
            if (pk == null || pk == "" ||
                    (pk.length() != 512 && pk.length() != 64))
                throw new Exception("Invalid public key");

            whitelistRepository.deleteAllByPk(pk);
            log(username, "Public key: \"" + pk + "\" is now removed from the whitelist\n");

            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<>(Response.STATUS_OK, null, null);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString());
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<OnBoardResp> restOnBoard(OnBoard onBoard, HttpServletResponse servletResponse) {
        String username = "";
        try {
            username = onBoard.getGid();
            log(username,
                    "\n=========================================\n" +
                    "Server received onboarding request\n" +
                    "=========================================\n");
            // Process EK cert
            String eKPubKey = null;
            String pubKey = null;
            if (onBoard.getEkCrt() != null && onBoard.getEkCrt() != "") {
                byte[] crt_der = Hex.decode(onBoard.getEkCrt());
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream bytes = new ByteArrayInputStream(crt_der);
                X509Certificate eKCert = (X509Certificate) certFactory.generateCertificate(bytes);
                RSAPublicKey key = (RSAPublicKey)eKCert.getPublicKey();
                caManager.verify(eKCert);
                // Read EK pubkey from cert
                eKPubKey = Utils.encodeEkPubKey(key);
                pubKey = Utils.getPubKey(key);
                log(username, "EK certificate chain verified ok. Read EK public key from certificate: " + eKPubKey + "\n");
            } else if (onBoard.getEkPub() != null && onBoard.getEkPub() != "") {
                /* Cater for simulated TPM, no EK cert is available for verification */
                eKPubKey = onBoard.getEkPub();
                log(username, "EK certificate chain not available.\nReceived EK public key instead: " + eKPubKey + "\n");
            }

            // Check device is whitelisted
            User user = userRepository.findByUsername(username);
            if (user == null) {
                throw new Exception("User not found");
            }
            if (user.isWhitelistisactivated()) {
                com.ifx.server.entity.Whitelist wl1 = whitelistRepository.findByPk(pubKey.toUpperCase());
                com.ifx.server.entity.Whitelist wl2 = whitelistRepository.findByPk(pubKey.toLowerCase());
                if (wl1 == null && wl2 == null) {
                    throw new Exception("Device is not whitelisted to use this service. Consider adding: \""
                            + pubKey + "\" to whitelist");
                }
            }

            // Prevent DoS
            if (deviceRepository.count() > 100) {
                throw new Exception("exceeded maximum device registration, please contact server admin");
            }

            // Check device uniqueness
            Device deviceFound = deviceRepoService.findByDeviceEk(eKPubKey);
            if (deviceFound != null && deviceFound.getState() != Device.STATE_PENDING)
                throw new Exception("Device is registered");

            // Get SRK pub
            String srkPub = onBoard.getSrkPub();
            log(username, "Received SRK public key: " + srkPub + "\n");

            /************************************************/
            // Generate a software HMAC key
            DuplicateHMAC duplicateHMAC = new DuplicateHMAC();
            duplicateHMAC.genKey();

            // Duplicate the HMAC key
            duplicateHMAC.duplicate(Utils.rxConvoyPubKey(srkPub));
            byte[] innerWrapperKey = duplicateHMAC.innerWrapperKey; // use same inner wrap key for subsequence duplication

            log(username, "Generated HMAC key, encrypted using parent key (SRK) and inner wrap key: " + Hex.toHexString(innerWrapperKey) + "\n");
            /************************************************/

            /************************************************/
            // Generate a software RSA key
            DuplicateRSA duplicateRSA = new DuplicateRSA();
            duplicateRSA.genKey();

            // Duplicate the RSA key
            duplicateRSA.innerWrapperKey = innerWrapperKey; // use same inner wrap key as HMAC
            duplicateRSA.duplicate(Utils.rxConvoyPubKey(srkPub));

            log(username, "Generated RSA key, encrypted using SRK and inner wrap key\n");
            /************************************************/

            /************************************************/
            // Generate a software ECC key
            DuplicateECC duplicateECC = new DuplicateECC();
            duplicateECC.genKey();

            // Duplicate the RSA key
            duplicateECC.innerWrapperKey = innerWrapperKey; // use same inner wrap key as HMAC
            duplicateECC.duplicate(Utils.rxConvoyPubKey(srkPub));

            log(username, "Generated ECC key, encrypted using SRK and inner wrap key\n");
            /************************************************/

            // Make credential
            byte[] srkName = Utils.getKeyName(Utils.rxConvoyPubKey(srkPub));
            Credential cred = new Credential(Utils.rxConvoyPubKey(eKPubKey), srkName, innerWrapperKey);
            cred.makeCredential();
            log(username, "Encrypted inner wrap key using TPM make credential feature\n");

            // Generate device id, resolve conflict if there is one
            byte[] deviceID;
            do {
                deviceID = Utils.getRandom(8);
                Device device = deviceRepoService.findByDeviceName(Hex.toHexString(deviceID));
                if ((device != null && device.getState() == Device.STATE_PENDING)
                    || (device == null))
                    break;
            } while(true);
            log(username, "Generated unique device id: " + Hex.toHexString(deviceID) + "\n");

            // Encrypt device ID
            byte[] encryptedDeviceID = Utils.encryptAesCfb(innerWrapperKey, deviceID);
            log(username, "Encrypted device id using inner wrap key" + "\n");

            // Construct response:
            // - encrypted device ID
            // - credential
            // - duplicated keys (HMAC, RSA, ECC)
            String encClientID = Hex.toHexString(encryptedDeviceID);

            String credential = cred.txConvoyCredential();
            String encSecret = cred.txConvoyEncSecret();
            Cred rCred = new Cred(credential, encSecret);

            String duplicate = duplicateHMAC.txConvoyDuplicate();
            String dupPub = duplicateHMAC.txConvoyDuplicatePub();
            String encSeed = duplicateHMAC.txConvoyEncryptedSeed();
            Dup rDupHMAC = new Dup(duplicate, dupPub, encSeed);

            duplicate = duplicateRSA.txConvoyDuplicate();
            dupPub = duplicateRSA.txConvoyDuplicatePub();
            encSeed = duplicateRSA.txConvoyEncryptedSeed();
            Dup rDupRSA = new Dup(duplicate, dupPub, encSeed);

            duplicate = duplicateECC.txConvoyDuplicate();
            dupPub = duplicateECC.txConvoyDuplicatePub();
            encSeed = duplicateECC.txConvoyEncryptedSeed();
            Dup rDupECC = new Dup(duplicate, dupPub, encSeed);

            // Generate random challenge
            String challenge = Hex.toHexString(Utils.getRandom(32));

            // Insert device info into database
            Device d;
            if (deviceFound != null) d = deviceFound;
            else d = new Device();
            d.setEk(eKPubKey);
            d.setState(Device.STATE_PENDING);
            d.setGid(onBoard.getGid());
            d.setName(Hex.toHexString(deviceID));
            d.setChallenge(challenge);
            d.setHmacPub(duplicateHMAC.exportPub());
            d.setHmacPriv(duplicateHMAC.exportPriv());
            d.setRsa(duplicateRSA.exportPub());
            d.setEcc(duplicateECC.exportPub());
            deviceRepoService.create(d);

            // Generate response
            log(username, "Sending response to requester, comprises:\n" +
                    "  - Encrypted device id\n" +
                    "  - Encrypted inner wrap key (TPM make credential)\n" +
                    "  - Encrypted HMAC, RSA, and ECC keys (TPM duplicate)\n" +
                    "  - A challenge value to be signed by requester using the 3 keys\n");
            OnBoardResp resp = new OnBoardResp(encClientID, rCred, rDupHMAC, rDupRSA, rDupECC, challenge);
            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<OnBoardResp>(Response.STATUS_OK, resp);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<OnBoardResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<OnBoardAckResp> restOnBoardAck(OnBoardAck onBoardAck, HttpServletResponse servletResponse) {
        String username = "";
        try {
            String name = onBoardAck.getId();
            Device device = deviceRepoService.findByDeviceName(name);

            if (device == null)
                throw new Exception("device not registered");

            username = device.getGid();
            log(username,
                    "\n=========================================\n" +
                        "Server received onboarding acknowledgement\n" +
                        "=========================================\n");

            if (device.getState() != Device.STATE_PENDING) {
                if (device.getState() == Device.STATE_ACTIVE)
                    throw new Exception("device is already registered");
                else if (device.getState() == Device.STATE_DEAD)
                    throw new Exception("device life cycle has been terminated");
            }

            String challenge = device.getChallenge();
            if (challenge == "" || challenge == null)
                throw new Exception("unable to retrieve challenge");

            // Verify HMAC
            DuplicateHMAC hmac = new DuplicateHMAC();
            hmac.importPub(device.getHmacPub());
            hmac.importPriv(device.getHmacPriv());
            hmac.rxConvoySignature(challenge, onBoardAck.getSigHmac());
            if (!hmac.verify())
                throw new Exception("bad HMAC-based signature");
            log(username, "HMAC-based signature verified ok\n");

            // Verify RSA
            DuplicateRSA rsa = new DuplicateRSA();
            rsa.importPub(device.getRsa());
            rsa.rxConvoySignature(challenge, onBoardAck.getSigRsa());
            if (!rsa.verify())
                throw new Exception("bad RSA-based signature");
            log(username, "RSA-based signature verified ok\n");

            // Verify ECC
            DuplicateECC ecc = new DuplicateECC();
            ecc.importPub(device.getEcc());
            ecc.rxConvoySignature(challenge, onBoardAck.getSigEcc());
            if (!ecc.verify())
                throw new Exception("bad ECC-based signature");
            log(username, "ECC-based signature verified ok\n");

            // Activate device
            device.setChallenge(""); // to invalidate a challenge
            device.setState(Device.STATE_ACTIVE);
            deviceRepository.save(device);
            log(username, "Onboarding successfully\n");

            // Update frontend device table
            simpMessagingTemplate.convertAndSendToUser(username, "/topic/private",
                    new Response<DeviceInfo>(Response.STATUS_OK, new DeviceInfo(device)));

            // Generate response
            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<OnBoardAckResp>(Response.STATUS_OK, null);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<OnBoardAckResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<ChallengeResp> restGetChallenge(Challenge challenge, HttpServletResponse servletResponse) {
        String username = "";
        try {
            String name = challenge.getId();
            Device device = deviceRepoService.findByDeviceName(name);

            if (device == null || device.getState() != Device.STATE_ACTIVE)
                throw new Exception("device not registered");

            username = device.getGid();
            log(username,
                    "\n=========================================\n" +
                        "Server received get challenge request\n" +
                        "=========================================\n");

            // Generate random challenge
            String ch = Hex.toHexString(Utils.getRandom(32));
            log(username, "Generated challenge value to be signed by requester: " + ch + "\n");

            // Record the challenge
            device.setChallenge(ch);
            deviceRepository.save(device);

            // Generate response
            log(username, "Sending challenge to requester\n");
            ChallengeResp resp = new ChallengeResp(ch);
            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<ChallengeResp>(Response.STATUS_OK, resp);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<ChallengeResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<KeyExchangeResp> restKeyExchange(KeyExchange keyExchange, HttpServletResponse servletResponse) {
        String username = "";
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String name = authentication.getName();
            String devSeed = keyExchange.getSeed();
            Device device = deviceRepoService.findByDeviceName(name);
            if (device == null)
                throw new Exception("device not registered");

            // String has to be 32 long = 16 bytes of hexadecimal
            if (devSeed.length() != 32)
                throw new Exception("invalid seed length");

            username = device.getGid();
            log(username,
                    "\n=========================================\n" +
                        "Server received key exchange request\n" +
                        "=========================================\n");

            // Generate server partial seed
            byte[] serverSeed = Utils.getRandom(16);

            // Concatenate seed (server seed 16B + device seed 16B)
            byte[] deviceSeed = Hex.decode(devSeed);
            byte[] seed = new byte[32];
            System.arraycopy(serverSeed, 0, seed, 0, 16);
            System.arraycopy(deviceSeed, 0, seed, 16, 16);
            log(username, "Constructed shared key derivation seed: " + Hex.toHexString(seed) + "\n");

            // Generate HMAC-based shared key
            DuplicateHMAC hmac = new DuplicateHMAC();
            hmac.importPub(device.getHmacPub());
            hmac.importPriv(device.getHmacPriv());
            byte[] sharedKey = hmac.sign(seed);
            log(username, "Derived AES-based shared key: " + Hex.toHexString(sharedKey) + "\n");

            // Store shared key
            device.setSharedKey(Hex.toHexString(sharedKey));
            deviceRepository.save(device);

            // Update frontend device table
            simpMessagingTemplate.convertAndSendToUser(username, "/topic/private",
                    new Response<DeviceUpdate>(Response.STATUS_OK, new DeviceUpdate(device)));

            // Construct response
            log(username, "Sending server seed to requester\n");
            KeyExchangeResp resp = new KeyExchangeResp(Hex.toHexString(serverSeed), null, null);
            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<>(Response.STATUS_OK, null, resp);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public ResponseEntity<Resource> restDownload(@RequestBody Download download) {
        String username = "";
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String name = authentication.getName();
            Device device = deviceRepoService.findByDeviceName(name);
            if (device == null)
                throw new Exception("device not registered");

            username = device.getGid();
            log(username,
                    "\n=========================================\n" +
                        "Server received download request\n" +
                        "=========================================\n");

            String fileName = download.getName();
            if (fileName == null || fileName == "" ) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }

            // Prep AES engine
            byte[] secret = Hex.decode(device.getSharedKey()); //javax.xml.bind.DatatypeConverter.parseHexBinary
            SecretKeySpec encryptKey = new SecretKeySpec(secret, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptKey);

            byte[] stream = null;
            AlgorithmParameters params = cipher.getParameters();
            if (resourceVideoBeach.getFilename().contains(fileName)) {
                log(username, "Encrypted video (" + fileName + ") using shared key\n");
                stream = resourceVideoBeach.getInputStream().readAllBytes();
            } else if (resourceTextPlain.getFilename().contains(fileName)) {
                log(username, "Encrypted file (" + fileName + ") using shared key\n");
                stream = resourceTextPlain.getInputStream().readAllBytes();
            } else if (fileName.equals("hex")) {
                log(username, "Encrypted 4 bytes of data 0xdeadbeef using shared key\n");
                stream = new byte[]{(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF};
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }

            byte[] encryptedStream = cipher.doFinal(stream);
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
            byte[] out = new byte[iv.length + encryptedStream.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(encryptedStream, 0, out, iv.length, encryptedStream.length);
            ByteArrayResource body = new ByteArrayResource(out);

            // Send encrypted video via octet stream
            log(username, "Sending encrypted blob to requester\n");
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(body.contentLength())
                    .body(body);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    public Response<String> restDeregister2(HttpServletResponse servletResponse) {
        String username = "";
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String name = authentication.getName();
            Device device = deviceRepoService.findByDeviceName(name);
            if (device == null)
                throw new Exception("device not registered");

            username = device.getGid();
            log(username,
                    "\n=========================================\n" +
                        "Server received de-registration request\n" +
                        "=========================================\n");

            deviceRepository.deleteByName(name);

            log(username, "Device is now removed from database");
            servletResponse.setStatus(HttpServletResponse.SC_OK);
            return new Response<>(Response.STATUS_OK, null, null);
        } catch (Exception e) {
            log(username, "Failed with error: " + e.toString() + "\n");
            servletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new Response<>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////

    private void getSecurityFilterChain() {
        FilterChainProxy filterChainProxy = (FilterChainProxy) springSecurityFilterChain;
        List<SecurityFilterChain> list = filterChainProxy.getFilterChains();
        list.stream()
                .flatMap(chain -> chain.getFilters().stream())
                .forEach(filter -> System.out.println(filter.getClass()));
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
