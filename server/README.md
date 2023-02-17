# Introduction

The Endorsement Key (EK) based device onboarding is a mechanism to register a device on a cloud service using EK as device identity without the need to provision TPM with additional key or certificate. Moreover, it is possible to perform secure transfer of secret keys (HMAC/RSA/ECC) from a server to a device’s TPM. Depending on the application, these keys can be used for different purposes, e.g., second layer data encryption/decryption.

For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/ek-based-onboarding-optiga-tpm/raw/master/documents/tpm-appnote-ek-based-onboarding.pdf).

# Build

Install Maven:
```
$ sudo apt install maven
```
Build project:
 ```
 $ mvn package
``` 
JAR file location: `server/target/server-0.0.1-SNAPSHOT.jar`

# Run

Install openJDK:
```
$ sudo apt-get install openjdk-9-jre
```
Run server. On Raspberry Pi you may need root privilege to access port 80/443.
```
$ sudo java -jar server-0.0.1-SNAPSHOT.jar
```

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
