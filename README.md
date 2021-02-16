# Introduction
This document explains how an OPTIGA™ TPM SLx 9670 TPM2.0 can be used on a Raspberry Pi® to perform the Endorsement Key (EK) based device onboarding.

The Endorsement Key (EK) based device onboarding is a mechanism to register a device on a cloud service using EK as device identity without the need to provision TPM with additional key or certificate. Moreover, it is possible to perform secure transfer of secret keys (HMAC/RSA/ECC) from a server to a device’s TPM. Depending on the application, these keys can be used for different purposes, e.g., second layer data encryption/decryption.

# Prerequisites

Hardware prerequisites:
- [Raspberry Pi® 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/)
- [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)\
  <img src="https://github.com/Infineon/ek-based-onboarding-optiga-tpm/raw/master/media/IRIDIUM9670-TPM2.png" width="30%">

# Getting Started

For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/ek-based-onboarding-optiga-tpm/raw/master/documents/tpm-appnote-ek-based-onboarding.pdf).

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
