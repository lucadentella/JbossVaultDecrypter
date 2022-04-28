# JbossVaultDecrypter
Java utility to view the content of a **Jboss Vault**.

## How to use
Jboss Password Vault is made by two files:
 - **VAULT.dat**, the data repository (key/value pairs)
 - **vault.keystore**, a Java keystore which contains the "admin key" used to encrypt vault entries

To be able to open the Vault, you need the following information:
 - **keystorePassword**, encoded form of the keystore password
 - **keystoreSalt**, salt used to encode the password
 - **keystoreIteration**, iteration number used to encode the password

You can find the information in Jboss standalone.xml file.

Run the utility with:
```
java -jar vaultDecrypter.jar <VaultFile> <KeystoreFile> <KeystorePassword> <KeystoreSalt> <KeystoreIteration>
```

## How to compile
The following libraries are required to compile and run the code:
 - [picketbox-5.1.0.Final.jar](https://mvnrepository.com/artifact/org.picketbox/picketbox/5.1.0.Final)
 - [jboss-logging-3.4.3.Final.jar](https://mvnrepository.com/artifact/org.jboss.logging/jboss-logging/3.4.0.Final)
