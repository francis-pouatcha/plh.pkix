package org.adorsys.plh.pkix.core.smime.plooh;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;

public class ContactIndexerDefault implements ContactIndexer{
	// The cache. TODO replace with clean cache.
	// The key is the keyStoreId, or the relative file name of the 
	// keyStore in the scope of the FileContainer.
	private final Map<String, KeyStoreWraper> contacts = new HashMap<String, KeyStoreWraper>();
	
	private ContactIndex contactIndex;	
	private final FileWrapper contactsDir;
	// only key store carrying a private key
	private Map<String, List<String>> keyStoreAliasByEmails;

	public ContactIndexerDefault(FileWrapper contactsDir) {
		this.contactsDir = contactsDir;
		rescan();
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
	}

	private void rescan(){
		contacts.clear();
		contactIndex = new ContactIndex();
		String[] list = contactsDir.list();
		if(list==null || list.length==0) return;
		for (String keyStoreId : list) {
			KeyStoreWraper keyStoreWraper = loadKeyStore(keyStoreId);
			indexKeyStore(keyStoreWraper,null);
		}
	}

	public void indexKeyStore(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		if(keyStoreAliases==null)keyStoreAliases = keyStoreWraper.keyStoreAliases();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			getContactIndex().addContact(keyStoreWraper.getKeyStoreId(), keyStoreAlias);
		}
		emailIndex(keyStoreWraper, keyStoreAliases);
	}
	
	private void emailIndex(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		List<TrustedCertificateEntry> entries = keyStoreWraper.findEntriesByAlias(TrustedCertificateEntry.class, keyStoreAliases);
		for (TrustedCertificateEntry trustedCertificateEntry : entries) {
			X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(trustedCertificateEntry.getTrustedCertificate());
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, TrustedCertificateEntry.class);
			addToEmailIndex(certHolder, keyStoreAlias);
		}
		
		List<PrivateKeyEntry> privateKeyEntries = keyStoreWraper.findEntriesByAlias(PrivateKeyEntry.class, keyStoreAliases);
		for (PrivateKeyEntry privateKeyEntry : privateKeyEntries) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certificateHolder, PrivateKeyEntry.class);
			addToEmailIndex(certificateHolder, keyStoreAlias);
		}
	}
	
	private void addToEmailIndex(X509CertificateHolder certHolder, KeyStoreAlias keyStoreAlias){
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
		for (String subjectEmail : subjectEmails) {
			List<String> parsedEmailAddresses = X500NameHelper.parseEmailAddress(subjectEmail);
			for (String parsedEmailAddress : parsedEmailAddresses) {
				List<String> aliases = keyStoreAliasByEmails.get(parsedEmailAddress);
				if(aliases==null){
					aliases=new ArrayList<String>();
					keyStoreAliasByEmails.put(parsedEmailAddress, aliases);
				}
				aliases.add(keyStoreAlias.getAlias());
			}
		}
	}
	
	public KeyStoreWraper loadKeyStore(String keyStoreId){
		KeyStoreWraper keyStoreWraper = contacts.get(keyStoreId);
		if(keyStoreWraper!=null) return keyStoreWraper;		
		
		FileWrapper keyStoreFile = contactsDir.newChild(keyStoreId);
		keyStoreWraper = new KeyStoreWraper(keyStoreFile, null, contactsDir.getKeyStoreWraper().getKeyStoreId().toCharArray());
		if(keyStoreWraper!=null)
			contacts.put(keyStoreId, keyStoreWraper);
		return keyStoreWraper;
	}
	
}
