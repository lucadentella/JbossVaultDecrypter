package org.picketbox.plugins.vault;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.util.Base64;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.security.Util;
import org.jboss.security.plugins.PBEUtils;
import org.picketbox.util.EncryptionUtil;
import org.picketbox.util.StringUtil;

// From https://github.com/picketbox/picketbox/blob/master/security-jboss-sx/jbosssx/src/main/java/org/picketbox/plugins/vault/PicketBoxSecurityVault.java

public class vaultDecrypter {

	private static final String PASS_MASK_PREFIX = "MASK-";
	private static final  String encryptionAlgorithm = "AES";
	private static final String defaultKeyStoreType = "JCEKS";
	
	public vaultDecrypter(String vaultFile, String keystoreFile, String keystorePassword, String keystoreSalt, int keystoreIteration) throws Exception {
			
		System.out.println("vaultDecrypter 1.0");
		System.out.println();
		System.out.println("VAULT: " + vaultFile);
		System.out.println("KEYSTORE: " + keystoreFile);
		System.out.println();
		
		// 1. decode keystore password
		char[] keystoreDecodedPassword = loadKeystorePassword(keystorePassword, keystoreSalt, keystoreIteration);
		
		// 2. open keystore and get admin key
		SecretKeySpec secretKey = new SecretKeySpec(getAdminKey(keystoreFile, keystoreDecodedPassword).getEncoded(), encryptionAlgorithm);		
		
		// 3. load the serialized VAULT object 
		if(!new File(vaultFile).exists()) {
			System.out.println("[!] Vault file not found");
			System.exit(1);
		}			
		ObjectInputStream objStream = new ObjectInputStream(new FileInputStream(vaultFile));
		SecurityVaultData obj = (SecurityVaultData)objStream.readObject();
		System.out.println("[+] Vault object loaded, entries: ");
		
		// 4. get the data keys
		Set<String> keys = obj.getVaultDataKeys();
		for(String key: keys) {
			
			// 5. keys are in format keyAlias (empty)::vaultBlock::attributeName
			int separatorPosition = key.indexOf(StringUtil.PROPERTY_DEFAULT_SEPARATOR);
			String keyAlias = "";
			String vaultBlock = key.substring(0, separatorPosition);
			String attributeName = key.substring(separatorPosition + 2);	
			
			// 6. use admin key to decrypt the key value
			byte[] encryptedValue = obj.getVaultData(keyAlias, vaultBlock, attributeName);
			EncryptionUtil encUtil = new EncryptionUtil("AES", 128);
			char[] plainValue = new String(encUtil.decrypt(encryptedValue, secretKey)).toCharArray();
			
			System.out.print(" [-] " + key + "=");
			System.out.println(plainValue);
		}
		objStream.close();
		System.out.println();
		System.out.println("done!");
	}
	
	private char[] loadKeystorePassword(String passwordDef, String salt, int iterationCount) throws Exception {

		final char[] password;

		if(passwordDef.startsWith(PASS_MASK_PREFIX)) {
			String keystorePass = decode(passwordDef, salt, iterationCount);
			password = keystorePass.toCharArray();
			System.out.println("[+] Keystore decoded password: " + keystorePass);
		}
		else {
			password = Util.loadPassword(passwordDef);
			System.out.println("[+] Keystore password is already decoded: " + passwordDef);
		}
		
		return password;
	}	
	
	private String decode(String maskedString, String salt, int iterationCount) throws Exception {
		
		String pbeAlgo = "PBEwithMD5andDES";
		
		if (maskedString.startsWith(PASS_MASK_PREFIX)) {

			SecretKeyFactory factory = SecretKeyFactory.getInstance(pbeAlgo);

			char[] password = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
			PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(), iterationCount);
			PBEKeySpec keySpec = new PBEKeySpec(password);
			SecretKey cipherKey = factory.generateSecret(keySpec);

			maskedString = maskedString.substring(PASS_MASK_PREFIX.length());
			String decodedValue = PBEUtils.decode64(maskedString, pbeAlgo, cipherKey, cipherSpec);
			maskedString = decodedValue;
		}
		return maskedString;
	}

	private SecretKey getAdminKey(String keystoreFile, char[] keystoreDecodedPassword) throws Exception {
		
		// Check if keystore file exists
		if(!new File(keystoreFile).exists()) {
			System.out.println("[!] Keystore file not found");
			System.exit(1);
		}
		
		// Create a new keystore instance and open the keystore file
		KeyStore keystore = KeyStore.getInstance(defaultKeyStoreType);
		keystore.load(new FileInputStream(keystoreFile), keystoreDecodedPassword);
		
		// Get the "vault" entry from the keystore 
		Entry e = keystore.getEntry("vault", new KeyStore.PasswordProtection(keystoreDecodedPassword));		
		SecretKey adminKey = ((KeyStore.SecretKeyEntry)e).getSecretKey();
		System.out.println("[+] Admin key (base64): " + Base64.getEncoder().encodeToString(adminKey.getEncoded()));
		
		return adminKey;
	}
	
	public static void main(String[] args) throws Exception {

		if(args.length != 5) {
			System.out.println("Usage: vaultDecrypter <VaultFile> <KeystoreFile> <KeystorePassword> <KeystoreSalt> <KeystoreIteration>");
			System.exit(1);
		}	
		
		new vaultDecrypter(args[0], args[1], args[2], args[3], Integer.parseInt(args[4]));			
	}

}
