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
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;

public class ContactIndexerBootStrap implements ContactIndexer {
	
	private final ContactIndex contactIndex = new ContactIndex();	
	// only key store carrying a private key
	private final Map<String, List<String>> keyStoreAliasByEmails = new HashMap<String, List<String>>();
	private final KeyStoreWraper mainKeyStoreWraper;

	public ContactIndexerBootStrap(KeyStoreWraper mainKeyStoreWraper) {
		this.mainKeyStoreWraper = mainKeyStoreWraper;
		// Process main
		indexKeyStore(mainKeyStoreWraper, null);
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
	}

	public void indexKeyStore(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		if(keyStoreAliases==null)keyStoreAliases = keyStoreWraper.keyStoreAliases();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			getContactIndex().addContact(keyStoreWraper.getKeyStoreId(),keyStoreAlias);
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
		String mainKeyStoreWraperId = mainKeyStoreWraper.getKeyStoreId();
		if(mainKeyStoreWraperId.equals(keyStoreId)) return mainKeyStoreWraper;

		throw new IllegalStateException("Supports only the main key store.");
	}
	
}
