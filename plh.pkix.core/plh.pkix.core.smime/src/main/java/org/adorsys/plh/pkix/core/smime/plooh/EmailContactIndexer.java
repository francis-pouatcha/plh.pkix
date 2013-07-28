package org.adorsys.plh.pkix.core.smime.plooh;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;

public class EmailContactIndexer {

	private final Map<String, List<String>> keyStoreAliasByEmails = new HashMap<String, List<String>>();
	
	public void emailIndex(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		List<TrustedCertificateEntry> entries = keyStoreWraper.findEntriesByAlias(TrustedCertificateEntry.class, keyStoreAliases);
		for (TrustedCertificateEntry trustedCertificateEntry : entries) {
			X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(trustedCertificateEntry.getTrustedCertificate());
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, TrustedCertificateEntry.class);
			addToEmailIndex(keyStoreAliasByEmails, certHolder, keyStoreAlias);
		}
		
		List<PrivateKeyEntry> privateKeyEntries = keyStoreWraper.findEntriesByAlias(PrivateKeyEntry.class, keyStoreAliases);
		for (PrivateKeyEntry privateKeyEntry : privateKeyEntries) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
			KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certificateHolder, PrivateKeyEntry.class);
			addToEmailIndex(keyStoreAliasByEmails, certificateHolder, keyStoreAlias);
		}
	}
	
	private static void addToEmailIndex(Map<String, List<String>> keyStoreAliasByEmails, X509CertificateHolder certHolder, KeyStoreAlias keyStoreAlias){
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

	public Set<String> findKeyStoreAliasesByEmail(String... emails){
		Set<String> result = new HashSet<String>();
		for (String email : emails) {
			List<String> list = keyStoreAliasByEmails.get(email);
			if(list!=null) result.addAll(list);
		}
		return result;
	}
}
