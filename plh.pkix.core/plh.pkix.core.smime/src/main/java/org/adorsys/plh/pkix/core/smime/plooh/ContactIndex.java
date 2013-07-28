package org.adorsys.plh.pkix.core.smime.plooh;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.apache.commons.lang3.StringUtils;

/**
 * Simple index file of all contacts maintained by an end entity.
 * 
 * Each contact is represented by one or many records.
 * 
 * Each record has the form <StrictEmailAddress>=<KeyStoreLocation>.
 * 
 * Many Emails can point to the same key store. Meaning that they represent
 * the same end entity. Each email is associated with atleast one certificate.
 * 
 * A single certificate might also represent many emails.
 * 
 * Emails must be store in the subjectAlternativeName extension of the certificate.
 * 
 * If the user has many emails and among them a prefered email address, it can be stored
 * in the <emailAddress> component of the common name. Otherwise the application
 * will consider prefered the first email address in the list of emails listed in the 
 * subjectAlternativeName extension.
 * 
 * The index key is the lower case strict version of the email. This means that 
 * 
 * <Francis Pouatcha Signing>"fpo@me.com" is equivalent to 
 * <Francis Pouatcha Ca>"fpo@me.com" because both map to fpo@me.com.
 * 
 * Is an email address is reserved by an endentity, the application will
 * not allow the storage of that email for another end entity. That application
 * will refuse to import the corresponding contact.
 * 
 * If a certificate is signed by a address authority, this certificate will have 
 * precedence over existing self signed certificates.
 * 
 * @author francis
 *
 */
public class ContactIndex {
	
	private Map<KeyStoreAlias, String> keyAlias2KeyStoreId = new HashMap<KeyStoreAlias, String>();
	private Map<String, String> publicKeyId2KeyStoreId = new HashMap<String, String>();

	public void addContact(String keyStoreId, KeyStoreAlias keyStoreAlias){
		String keyStoreIdFound = keyAlias2KeyStoreId.get(keyStoreAlias);
		if(keyStoreIdFound!=null && !StringUtils.equalsIgnoreCase(keyStoreIdFound, keyStoreId)){
			throw new IllegalArgumentException("key alias already included in keystore : "+keyStoreIdFound + 
					" so it can not be indexed for " + keyStoreId);
		}
		
		String publicKeyIdHex = keyStoreAlias.getPublicKeyIdHex();
		keyStoreIdFound = publicKeyId2KeyStoreId.get(publicKeyIdHex);
		if(keyStoreIdFound!=null && !StringUtils.equalsIgnoreCase(keyStoreIdFound, keyStoreId)){
			throw new IllegalArgumentException("public key id already included in keystore : "+keyStoreIdFound + 
					" so it can not be indexed for " + keyStoreId);
		}

		keyAlias2KeyStoreId.put(keyStoreAlias, keyStoreId);
		publicKeyId2KeyStoreId.put(publicKeyIdHex, keyStoreId);
	}

	public Set<KeyStoreAlias> keyStoreAliases(){
		return keyAlias2KeyStoreId.keySet();
	}
	
	public String findByKeyStoreAlias(KeyStoreAlias keyStoreAlias){
		String keyStoreId = keyAlias2KeyStoreId.get(keyStoreAlias);
		if(keyStoreId!=null) return keyStoreId;
		String publicKeyIdHex = keyStoreAlias.getPublicKeyIdHex();
		if(publicKeyIdHex!=null) return publicKeyId2KeyStoreId.get(publicKeyIdHex);
		return null;
	}
	
	public String findByPublicKeyId(String publicKeyIdHex){
		return publicKeyId2KeyStoreId.get(publicKeyIdHex);
	}
}
