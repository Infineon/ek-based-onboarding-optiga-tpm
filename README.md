# Introduction

The Endorsement Key (EK) based device onboarding is a mechanism to register a device on a cloud service using EK as device identity without the need to provision TPM with additional key or certificate. Moreover, it is possible to perform secure transfer of secret keys (HMAC/RSA/ECC) from a server to a device’s TPM. Depending on the application, these keys can be used for different purposes, e.g., second layer data encryption/decryption.

For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/ek-based-onboarding-optiga-tpm/raw/master/documents/tpm-appnote-ek-based-onboarding.pdf).

# Run Scripts

Remember to launch the server before running scripts 0 to 9.

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
