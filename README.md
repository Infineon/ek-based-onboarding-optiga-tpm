# Introduction
This project explains how to use an OPTIGA™ TPM 2.0 on a Raspberry Pi to perform Endorsement Key (EK)-based device onboarding to a private cloud. EK-based device onboarding is a mechanism for registering a device on a cloud service using EK as the device identity, without the need to provision the TPM with an additional key or certificate. Additionally, there is a way to securely transfer server-generated keys (HMAC/RSA/ECC) to a TPM of a device. The in-transit encrypted key blobs can be associated with an EK, and as a result, the blobs can only be imported to a TPM that holds the specified EK. Depending on the application, these keys can be used for various purposes, such as data encryption/decryption and digital signing.

# Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Project Overview](#project-overview)**
- **[Preparing Raspberry Pi for First Use](#preparing-raspberry-pi-for-first-use)**
- **[Installing Software for First Use](#installing-software-for-first-use)**
- **[Operation Guide](#operation-guide)**
    - **[TPM Simulator](#tpm-simulator)**
    - **[Server](#server)**
    - **[Device](#device)**
- **[License](#license)**

# Prerequisites

There are two options for TPM usage: using an actual TPM or a simulated TPM.

<ins>Option 1:</ins><br>To use an actual TPM, you will need the following hardware:
- You can use either of the following TPM2.0 boards:
    - [IRIDIUM9670 TPM2.0 board](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)\
      <img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/IRIDIUM9670-TPM2.png" width="15%">
    - [OPTIGA™ TPM SLB 9672 RPI evaluation board](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-tpm-9672-rpi-eval/)\
      <img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/SLB9672-EVA-BOARD.png" width="20%">
- A [Raspberry Pi 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/) with TPM mounted.\
  <img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/raspberry-with-slb9670.png" width="30%">
  <img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/raspberry-with-slb9672.png" width="30%">

<ins>Option 2:</ins><br>For a simulated TPM, you can use any host machine with one of the following Linux distributions installed: Debian (Bullseye, Buster), Ubuntu (18.04, 20.04).

# Project Overview

The purpose of this project is to demonstrate the following flow:

| Flow  | Description |
|:---:|:---|
| 1. Onboarding | This step is performed once to onboard a device to a server and follows this sequence:<ul><li>The server verifies that the EK certificate is issued by Infineon's CA.</li><li>If the whitelist feature is enabled, only devices with a whitelisted EK public key can be onboarded.</li><li>Three TPM key objects (HMAC, RSA, and ECC) are generated on the server and transferred to the TPM of the device.</li></ul> |
| 2. Authentication | The authentication step requires the device to produce a total of three signatures using the three imported keys (for demonstration purposes only; in normal circumstances, a single signature may suffice). After a successful authentication, the device will receive a server-signed JWT-formatted token. The JWT is necessary for all subsequent communication with the server as proof of identity. The JWT is only valid for a limited period. The authentication step can be repeated to obtain a new JWT. |
| 3. Key Derivation and Second-Layer Encryption | This step demonstrates that the imported HMAC key can be used to add another layer of data encryption. A session-based encryption key can be derived using the HMAC function after exchanging seeds between the server and the device. |

# Preparing Raspberry Pi for First Use

Skip this section if you do not plan to use Raspberry Pi.

This section outlines the steps required to prepare an SD card image that can be used to boot a Raspberry Pi.

To begin, flash the Raspberry Pi OS image [2021-01-11 release](https://downloads.raspberrypi.org/raspios_armhf/images/raspios_armhf-2021-01-12/2021-01-11-raspios-buster-armhf.zip) onto a micro-SD card that is at least 8GB in size.

After inserting the SD card that you just flashed, boot up your Raspberry Pi. To enable TPM, execute the following commands:
```
$ sudo sh -c "echo 'dtoverlay=tpm-slb9670' >> /boot/config.txt"
```

Reboot the Raspberry Pi and check if TPM is activated by:
```
$ ls /dev | grep tpm
tpm0
tpmrm0
```

# Installing Software for First Use

Download package information:
```all
$ sudo apt update
```

Install generic packages:
```all
$ sudo apt -y install xxd jq maven openjdk-11-jre autoconf-archive libcmocka0 libcmocka-dev procps iproute2 build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev autoconf doxygen libjson-c-dev libini-config-dev libcurl4-openssl-dev uuid-dev pandoc acl libglib2.0-dev xxd curl
```

Install platform dependent packages on Ubuntu (18.04, 20.04):
```ubuntu-18.04,ubuntu-20.04
$ sudo apt -y install python-yaml
```

Install tpm2-tss:
```all
$ git clone https://github.com/tpm2-software/tpm2-tss ~/tpm2-tss
$ cd ~/tpm2-tss
$ git checkout 3.2.0
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig

# For debugging:
# Possible levels are: NONE, ERROR, WARNING, INFO, DEBUG, TRACE
# export TSS2_LOG=all+TRACE
```

Install tpm2-tools:
```all
$ git clone https://github.com/tpm2-software/tpm2-tools ~/tpm2-tools
$ cd ~/tpm2-tools
$ git checkout 5.2
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Install tpm2-abrmd:
```all
$ git clone https://github.com/tpm2-software/tpm2-abrmd ~/tpm2-abrmd
$ cd ~/tpm2-abrmd
$ git checkout 2.4.1
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Install libtpms-based TPM emulator on Ubuntu-22.04:
```all
# Install dependencies
$ sudo apt-get install -y dh-autoreconf libtasn1-6-dev net-tools libgnutls28-dev expect gawk socat libfuse-dev libseccomp-dev make libjson-glib-dev gnutls-bin

# Install libtpms-devel
$ git clone https://github.com/stefanberger/libtpms ~/libtpms
$ cd ~/libtpms
$ git checkout v0.9.5
$ ./autogen.sh --with-tpm2 --with-openssl
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig

# Install Libtpms-based TPM emulator
$ git clone https://github.com/stefanberger/swtpm ~/swtpm
$ cd ~/swtpm
$ git checkout v0.7.3
$ ./autogen.sh --with-openssl --prefix=/usr
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Download the project:
```
$ git clone https://github.com/wxleong/ek-based-onboarding-optiga-tpm ~/ek-based-onboarding-optiga-tpm
```

# Operation Guide

## TPM Simulator

If you don't plan to use TPM simulator, you may skip this section.

Start Libtpms-based TPM emulator:
```all
$ mkdir /tmp/emulated_tpm

# Create configuration files for swtpm_setup:
# - ~/.config/swtpm_setup.conf
# - ~/.config/swtpm-localca.conf
#   This file specifies the location of the CA keys and certificates:
#   - ~/.config/var/lib/swtpm-localca/*.pem
# - ~/.config/swtpm-localca.options
$ swtpm_setup --tpm2 --create-config-files overwrite,root

# Initialize the swtpm
$ swtpm_setup --tpm2 --config ~/.config/swtpm_setup.conf --tpm-state /tmp/emulated_tpm --overwrite --create-ek-cert --create-platform-cert --write-ek-cert-files /tmp/emulated_tpm

# Launch the swtpm
$ swtpm socket --tpm2 --flags not-need-init --tpmstate dir=/tmp/emulated_tpm --server type=tcp,port=2321 --ctrl type=tcp,port=2322 &   <--- to debug, add "--log level=?"
$ sleep 5
```

Copy swtpm CA certificates to the server source:
```all
# Root CA
$ openssl x509 -outform der -in ~/.config/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem -out ~/ek-based-onboarding-optiga-tpm/server/src/main/resources/rootCAs/swtpm-localca-rootca-cert.crt

# Intermediate CA
$ mkdir ~/ek-based-onboarding-optiga-tpm/server/src/main/resources/intermediateCAs
$ openssl x509 -outform der -in ~/.config/var/lib/swtpm-localca/issuercert.pem -out ~/ek-based-onboarding-optiga-tpm/server/src/main/resources/intermediateCAs/issuercert.crt
```

Start a session dbus which is limited to the current login session:
```all
$ sudo apt install -y dbus
$ export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
```

Start TPM resource manager:
```all
$ tpm2-abrmd --allow-root --session --tcti=swtpm:host=127.0.0.1,port=2321 &
$ sleep 5
```

## Server

Build and start the server:
```all
$ cd ~/ek-based-onboarding-optiga-tpm/server
$ mvn package
$ mvn spring-boot:run &
$ sleep 20
```

The server is ready for operation once you see the following message:
```
...
2023-02-17 07:52:53.582  INFO 8998 --- [main] o.s.m.s.b.SimpleBrokerMessageHandler     : Started.
2023-02-17 07:52:53.915  INFO 8998 --- [main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 443 (https) 80 (http) with context path ''
2023-02-17 07:52:53.916  INFO 8998 --- [main] com.ifx.server.ServerApplication         : Started ServerApplication in 3.51 seconds (JVM running for 3.732)
```

To view the webpage, open a web browser and navigate to https://localhost. A warning message may appear due to the server using a self-signed certificate. You can bypass this warning and proceed as usual. Once the webpage has loaded, click on "Start" in the upper menu bar to enter the sign-in page ([*Screenshot-1*](#screenshot-1)). Use the following credentials to sign in:

- Username: infineon
- Password: noenifni

Once you have logged in successfully, you will see that the dashboard page (as shown in [*Screenshot-2*](#screenshot-2) and [*Screenshot-3*](#screenshot-3)) has the following elements:

| Element  | Description |
|:---:|:---|
| A | The table displays a list of onboarded devices, along with a button for unpairing devices. |
| B | Display of server activity log. |
| C | Upload a CSV-formatted file containing a list of whitelisted EK public keys. |
| D | You can enable or disable the effect of whitelisting. If the option is disabled, a device can only be onboarded if its TPM is issued by Infineon. If the option is enabled, a device can only be onboarded if both of the following conditions are met:<ul><li>The TPM is issued by Infineon.</li><li>The EK public key is whitelisted.</li></ul>
| E | The table displays a list of whitelisted devices, along with a button for blacklisting devices. |

Screenshots:
<table>
<tr>
  <td><pre><i>Screenshot-1</i></pre></td>
  <td><a id="screenshot-1"><img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/dashboard-login.png" width="50%"></td>
</tr>
<tr></tr>
<tr>
  <td><pre><i>Screenshot-2</i></pre></td>
  <td><a id="screenshot-2"><img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/dashboard-1.png" width="50%"></td>
</tr>
<tr></tr>
<tr>
  <td><pre><i>Screenshot-3</i></pre></td>
  <td><a id="screenshot-3"><img src="https://github.com/wxleong/ek-based-onboarding-optiga-tpm/raw/develop-rework/media/dashboard-2.png" width="50%"></td>
</tr>
</table>

## Device

Depending on your choice of TPM:
- <ins>Hardware TPM</ins><br>
  Set the TCTI interface:
  ```
  $ export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
  ```
  Grant access permissions to the TPM device nodes:
  ```
  $ cd ~/ek-based-onboarding-optiga-tpm/device
  $ ./0_prep.sh
  ```
- <ins>Simulated TPM</ins><br>
  Set the TCTI interface:
  ```all
  $ export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
  ```

Once the server is up and running, execute the following scripts:
```all
$ cd ~/ek-based-onboarding-optiga-tpm/device
$ ./1_clean.sh
$ ./2_tpm-clear-init.sh
$ ./3_onboard-req.sh
$ ./4_tpm-key-import.sh
$ ./5_onboard-ack.sh
$ ./6_auth.sh
$ ./7_seed-exchange.sh
$ ./8_derive-aes-key.sh
$ ./9_secured-download.sh
```

You can find more information about each individual script in the following table:

<table>
  <tr></tr>
  <tr>
    <td><pre>0_prep.sh</pre></td>
    <td>Authorizes non-privileged access to the TPM device nodes.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>1_clean.sh</pre></td>
    <td>Cleans up the environment, erase non-essential files.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>2_tpm-clear-init.sh</pre></td>
    <td>Performs the following actions:<ol><li>Clears the TPM.</li><li>Creates an RSA EK.</li><li>Reads the RSA EK certificate.</li><li>Creates an RSA-based parent key that can be used as a wrapping key to securely transfer keys from a server to the TPM.</li><li>Creates a CSV-formatted whitelist containing a single EK public key taken from the EK certificate that you have just read.</li></ol>Note: If the whitelist feature is enabled, you must import the CSV file through the dashboard page (<a href="#screenshot-3"><i>Screenshot-3</i></a>) before proceeding.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>3_onboard-req.sh</pre></td>
    <td>Sends an onboarding request to the server, the request contains:<ul><li>The username ("infineon") to pair the device with.</li><li>The EK certificate.</li><li>The parent public key.</li></ul>The expected response from the server includes:<ul><li>A credential blob containing a decryption key (Ҡ).</li><li>An encrypted device ID, secured by Ҡ.</li><li>An encrypted HMAC-SHA256 key, secured by the parent key and an inner wrap key (Ҡ).</li><li>An encrypted RSA-2048 key, secured by the parent key and Ҡ.</li><li>An encrypted ECC NIST P-256 key, secured by the parent key and Ҡ.</li><li>A challenge.</li></ul>Note: if the whitelist feature is enabled, only whitelisted devices can be onboarded.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>4_tpm-key-import.sh</pre></td>
    <td>After receiving the server response:<ol><li>Perform TPM activate credential on the credential blob to recover the decryption key (Ҡ).</li><li>Decrypt the device ID using Ҡ.</li><li>Import the HMAC, RSA, and ECC keys into the TPM, using Ҡ as the inner wrap key and the RSA-based parent key.</li><li>Sign the challenge using the three imported keys.</li></ol></td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>5_onboard-ack.sh</pre></td>
    <td>Acknowledges the challenge by sending the three signatures to the server. Once the signatures are verified, the device is now successfully onboarded to the server.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>6_auth.sh</pre></td>
    <td>Starts an authentication sequence:<ol><li>Request a challenge from the server.</li><li>Sign the challenge using the three imported keys.</li><li>Upon receiving valid signatures, the server generates a token (JWT) and returns it to the device. The JWT contains a subject (device ID), a token validity period, and a server-generated signature.</li></ol>Now that you have obtained the necessary token for further communication with the server, it is mandatory to attach the JWT to all subsequent requests made to the server. This ensures that the server can authenticate your requests and authorize your access to the services.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>7_seed-exchange.sh</pre></td>
    <td>Performs seed exchange.</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>8_derive-aes-key.sh</pre></td>
    <td>The device uses the HMAC key and seed values to perform an HMAC operation, from which it derives a session-based AES key (AES-256/CBC/PKCS5Padding).</td>
  </tr>
  <tr></tr>
  <tr>
    <td><pre>9_secured-download.sh</pre></td>
    <td>After downloading encrypted media from the server, the device decrypts it using the AES key. The media that the device expects to receive include:<ul><li>A video in 3GP format (decrypted.3gp) that can be played using the Raspberry's built-in VLC Media Player.</li><li>A text file (decrypted.txt) containing the message "You have successfully decrypted this message."</li><li>A binary file (decrypted.hex) with a hexadecimal value of 0xdeadbeef (four bytes).</li></ul></td>
  </tr>
</table>

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
