# Websocket-Smart-Card-Signer
#### Websocket based (NO APPLET) Smart Card Digital Signature Application
Websocket-Smart-Card-Signer give the possibility to sign a document with a Smartcard, directly from the browser.
The application work as a Websocket server and is provided with a javascript client library that manage the comunications.
The application support the signature of online and local PDF documents in PAdES standard as well as the signature of any other kind of file in P7M using the CAdES standard.
This application depend on the projects [Java Native Interface for PKCS#11](https://github.com/damianofalcioni/jacknji11) and [IAIK PKCS#11 Wrapper](https://github.com/damianofalcioni/pkcs11wrapper).
More details on the features in the following.

## Features
- Websocket based. Did not use the deprecated APPLET technology
- PKCS#11 Access directly through [JNA](https://github.com/java-native-access/jna) or using [IAIK](http://jcewww.iaik.tu-graz.ac.at/sic/Products/Core_Crypto_Toolkits/JCA_JCE)
- Multi-OS and Multi-Smartcard Support
    - The following PKCS11 libraries are automatically identified in the system: "incryptoki2.dll", "bit4ipki.dll", "bit4opki.dll", "bit4xpki.dll", "OCSCryptoki.dll", "asepkcs.dll", "SI_PKCS11.dll", "cmP11.dll", "cmP11_M4.dll", "IpmPki32.dll", "IPMpkiLC.dll", "IpmPkiLU.dll", "bit4cpki.dll", "bit4p11.dll", "asepkcs.dll", "PKCS11.dll", "eTPKCS11.dll", "SSC_PKCS11.dll", "inp11lib.dll", "opensc-pkcs11.dll", "libbit4opki.so", "libbit4spki.so", "libbit4p11.so", "libbit4ipki.so", "opensc-pkcs11.so", "libeTPkcs11.so", "libopensc.dylib", "libbit4xpki.dylib", "libbit4ipki.dylib", "libbit4opki.dylib", "libASEP11.dylib", "libeTPkcs11.dylib"
    - Possibility to define custom PKCS11 libraries in case your Smartcard's PKCS11 is not listed above
- Access to all the Smartcard available certificates
- Recognition of multiple connected Smartcard
- Multi-Document signature
- P7M Signature in CAdES Standard format
- PDF Signature in PAdES Standard format
- Possibility configure the signature visibility and position in the PDF
- Avoid previous signature nesting
- Possibility to allow the signature only for specific user IDs
- Possibility to use a NTP service to automatically set the signature timestamp
- Validation of the generated signature
- Automatic diagnosis of Smartcard problems
- Possibility to be used as standalone document signature application using the try icon menu functions

## Live DEMO
Have a look at the [DEMO](https://wscs.000webhostapp.com/) (1h/day downtime expected)
The Jar is self-signed so in order to use the demo you must add a security exception in the java control panel for the site "https://wscs.000webhostapp.com/"

## Support Me <3
[![Buy me a coffee](https://user-images.githubusercontent.com/8982949/32890053-84c4cb1e-cacd-11e7-8eb1-0b0b7f666b5c.png)](https://www.paypal.me/damianofalcioni/0.99)