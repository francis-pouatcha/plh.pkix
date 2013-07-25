package org.adorsys.plh.pkix.core.smime.plooh;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraperUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Manages contacts of an end entity. Each contact is stored in a proper key store.
 * 
 * A contact is identified by the public key id of that contact. The message key of a 
 * contact carry the public key id of the corresponding ca key. The ca key can also carry
 * the public key id of the message key of the corresponding user.
 * 
 * Additionally, we maintain an identifier of the owner in each certificate and use if to
 * group all keys associated with party. This key will be take to be the public key id
 * of the first messaging key.
 * 
 * We have an email mapping that maintains the list of certificates associated with a given email address.
 * 
 * 
 * @author francis
 *
 */
public class ContactManagerImpl implements ContactManager {
	private final ContactIndexer contactIndexer;
	
	public ContactManagerImpl(FileWrapper contactsDir) {
		this.contactIndexer = new ContactIndexerDefault(contactsDir);
	}

	public ContactManagerImpl(KeyStoreWraper containerKeyStoreWraper) {
		this.contactIndexer = new ContactIndexerBootStrap(containerKeyStoreWraper);
	}
	
	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#addCertEntry(org.bouncycastle.cert.X509CertificateHolder)
	 */
	@Override
	public void addCertEntry(X509CertificateHolder certHolder) throws PlhCheckedException{
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, TrustedCertificateEntry.class);

		KeyStoreWraper keyStoreWraper = contactIndexer.loadKeyStore(keyStoreAlias.getEndEntityIdHex());
		keyStoreWraper.importCertificates(V3CertificateUtils.getX509BCCertificate(certHolder));

		contactIndexer.indexKeyStore(keyStoreWraper, Collections.singletonList(keyStoreAlias));
		
		for (ContactListener contactListener : contactListeners) {
			contactListener.contactAdded(certHolder);
		}
	}
	
	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#addPrivateKeyEntry(java.security.Key, java.security.cert.Certificate[])
	 */
	@Override
	public void addPrivateKeyEntry(Key key,Certificate[] chain) throws PlhCheckedException{
		X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(chain[0]);
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, PrivateKeyEntry.class);

		KeyStoreWraper keyStoreWraper = contactIndexer.loadKeyStore(keyStoreAlias.getEndEntityIdHex());
		keyStoreWraper.importCertificates(V3CertificateUtils.getX509BCCertificate(certHolder));
		keyStoreWraper.setPrivateKeyEntry(key, chain);

		contactIndexer.indexKeyStore(keyStoreWraper, Collections.singletonList(keyStoreAlias));
	}
	
	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#importIssuedCertificate(org.bouncycastle.asn1.x509.Certificate[])
`	 */
	@Override
	public void importIssuedCertificate(org.bouncycastle.asn1.x509.Certificate[] certArray) throws PlhCheckedException {
		X509CertificateHolder certHolder = new X509CertificateHolder(certArray[0]);
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certHolder, PrivateKeyEntry.class);

		KeyStoreWraper keyStoreWraper = contactIndexer.loadKeyStore(keyStoreAlias.getEndEntityIdHex());
		keyStoreWraper.importIssuedCertificate(certArray);

		contactIndexer.indexKeyStore(keyStoreWraper, Collections.singletonList(keyStoreAlias));
		
		for (ContactListener contactListener : contactListeners) {
			contactListener.issuedCertificateImported(certHolder);
		}
	}


	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryByAlias(java.lang.Class, java.util.List)
	 */
	@Override
	public <T extends Entry> T findEntryByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases) {
		if(keyStoreAliases==null || keyStoreAliases.isEmpty()) return null;
		
		// complement the aliases
		Set<KeyStoreAlias> aliases = new HashSet<KeyStoreAlias>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(keyStoreAlias.isComplete()) {
				aliases.add(keyStoreAlias);
			} else {
				List<KeyStoreAlias> selected = KeyStoreAlias.select(new ArrayList<KeyStoreAlias>(contactIndexer.getContactIndex().keyStoreAliases()), keyStoreAlias);
				aliases.addAll(selected);
			}
		}
		
		Set<String> visitedIds = new HashSet<String>();
		for (KeyStoreAlias keyStoreAlias : aliases) {
			String keyStoreId = contactIndexer.getContactIndex().findByKeyStoreAlias(keyStoreAlias);
			if(keyStoreId==null)continue;
			if(visitedIds.contains(keyStoreId))continue;
			visitedIds.add(keyStoreId);
			KeyStoreWraper loadedKeyStore = contactIndexer.loadKeyStore(keyStoreId);
			if(loadedKeyStore==null) continue;
			T entry = loadedKeyStore.findEntryByAlias(klass, new ArrayList<KeyStoreAlias>(aliases));
			if(entry!=null) return entry;
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntryByAlias(java.lang.Class, org.adorsys.plh.pkix.core.utils.KeyStoreAlias)
	 */
	@Override
	public <T extends Entry> T findEntryByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases) {
		return findEntryByAlias(klass, Arrays.asList(keyStoreAliases));
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesByAlias(java.lang.Class, java.util.List)
	 */
	@Override
	public <T extends Entry> List<T> findEntriesByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases) {
		if(keyStoreAliases==null || keyStoreAliases.isEmpty()) return Collections.emptyList();

		// complement the aliases
		Set<KeyStoreAlias> aliases = new HashSet<KeyStoreAlias>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(!keyStoreAlias.isComplete()) {
				List<KeyStoreAlias> selected = KeyStoreAlias.select(new ArrayList<KeyStoreAlias>(contactIndexer.getContactIndex().keyStoreAliases()), keyStoreAlias);
				aliases.addAll(selected);
			} else {
				aliases.add(keyStoreAlias);
			}
		}
		
		Set<String> visitedIds = new HashSet<String>();
		List<T> result = new ArrayList<T>();
		for (KeyStoreAlias keyStoreAlias : aliases) {
			String keyStoreId = contactIndexer.getContactIndex().findByKeyStoreAlias(keyStoreAlias);
			if(keyStoreId==null)continue;
			if(visitedIds.contains(keyStoreId))continue;
			visitedIds.add(keyStoreId);
			KeyStoreWraper loadedKeyStore = contactIndexer.loadKeyStore(keyStoreId);
			if(loadedKeyStore==null) continue;
			List<T> entries = loadedKeyStore.findEntriesByAlias(klass, new ArrayList<KeyStoreAlias>(aliases));
			if(entries!=null) result .addAll(entries);
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findEntriesByAlias(java.lang.Class, org.adorsys.plh.pkix.core.utils.KeyStoreAlias)
	 */
	@Override
	public <T extends Entry> List<T> findEntriesByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases) {
		return findEntriesByAlias(klass, Arrays.asList(keyStoreAliases));
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#keyStoreAliases()
	 */
	@Override
	public List<KeyStoreAlias> keyStoreAliases() {
		return new ArrayList<KeyStoreAlias>(contactIndexer.getContactIndex().keyStoreAliases());
	}


	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#getTrustAnchors()
	 */
	@Override
	public Set<TrustAnchor> getTrustAnchors(){
		Set<KeyStoreAlias> keyStoreAliases = contactIndexer.getContactIndex().keyStoreAliases();
		Set<KeyStoreAlias> selfSignedPrivate = new HashSet<KeyStoreAlias>();
		Set<KeyStoreAlias> selfSignedTrusted = new HashSet<KeyStoreAlias>();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			if(!keyStoreAlias.isSelfSigned()) continue;
			if(keyStoreAlias.isEntryType(PrivateKeyEntry.class)){
				selfSignedPrivate.add(keyStoreAlias);
			} else if (keyStoreAlias.isEntryType(TrustedCertificateEntry.class)){
				selfSignedTrusted.add(keyStoreAlias);
			}
		}
		
		Map<KeyStoreAlias, PrivateKeyEntry> privateKeyEntries = new HashMap<KeyStoreAlias, KeyStore.PrivateKeyEntry>();
		for (KeyStoreAlias keyStoreAlias : selfSignedPrivate) {
			String keyStoreId = contactIndexer.getContactIndex().findByKeyStoreAlias(keyStoreAlias);
			KeyStoreWraper keyStore = contactIndexer.loadKeyStore(keyStoreId);
			if(keyStore==null) continue;
			PrivateKeyEntry privateKeyEntry = keyStore.findEntryByAlias(PrivateKeyEntry.class, keyStoreAlias);
			if(V3CertificateUtils.isCaKey(privateKeyEntry.getCertificate())){
				privateKeyEntries.put(keyStoreAlias, privateKeyEntry);
			}
		}
		List<TrustedCertificateEntry> trustedCertificateEntries = new ArrayList<TrustedCertificateEntry>();
		Set<java.util.Map.Entry<KeyStoreAlias,PrivateKeyEntry>> privateKeyEntrySet = privateKeyEntries.entrySet();
		for (KeyStoreAlias keyStoreAlias : selfSignedTrusted) {
			String keyStoreId = contactIndexer.getContactIndex().findByKeyStoreAlias(keyStoreAlias);
			KeyStoreWraper keyStore = contactIndexer.loadKeyStore(keyStoreId);
			if(keyStore==null) continue;
			TrustedCertificateEntry trustedCertificateEntry = keyStore.findEntryByAlias(TrustedCertificateEntry.class, keyStoreAlias);
			// find the corresponding certificate signed by one of my private keys 
			// in that store
			for (Map.Entry<KeyStoreAlias, PrivateKeyEntry> entry : privateKeyEntrySet) {
				KeyStoreAlias privateKeyAlias = entry.getKey();
				KeyStoreAlias signedByme = new KeyStoreAlias(
						null,
						keyStoreAlias.getPublicKeyIdHex(), 
						keyStoreAlias.getSubjectKeyIdHex(), 
						privateKeyAlias.getSubjectKeyIdHex(), 
						null,
						null,
						TrustedCertificateEntry.class);
				TrustedCertificateEntry certSignedByme = keyStore.findEntryByAlias(TrustedCertificateEntry.class, signedByme);
				if(certSignedByme!=null){
					try {
						certSignedByme.getTrustedCertificate().verify(entry.getValue().getCertificate().getPublicKey());
						trustedCertificateEntries.add(trustedCertificateEntry);					
					} catch (Exception e) {
						// ignore certificate
					}
				}
			}
		}
		
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		for (Map.Entry<KeyStoreAlias, PrivateKeyEntry> entry : privateKeyEntrySet) {
			trustAnchors.add(new TrustAnchor((X509Certificate) entry.getValue().getCertificate(), null));
		}
		for (TrustedCertificateEntry entry : trustedCertificateEntries) {
			trustAnchors.add(new TrustAnchor((X509Certificate) entry.getTrustedCertificate(), null));
		}

		return trustAnchors;
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findCertStores(org.bouncycastle.cert.X509CertificateHolder)
	 */
	@Override
	public Set<CertStore> findCertStores(X509CertificateHolder... certificates) {
		return findCertStores(Arrays.asList(certificates));
	}

	/* (non-Javadoc)
	 * @see org.adorsys.plh.pkix.core.smime.contact.ContactManager#findCertStores(java.util.List)
	 */
	@Override
	public Set<CertStore> findCertStores(List<X509CertificateHolder> certificates) {
		List<X509CertificateHolder> researchList = KeyStoreWraperUtils.dropCertWithIncludedCa(certificates);
		List<X509CertificateHolder> signerCerts = new ArrayList<X509CertificateHolder>();
		signed: for (X509CertificateHolder signedCertificate : researchList) {
			X500Name subject = signedCertificate.getSubject();
			List<PrivateKeyEntry> privateCaEntries = findCaEntriesBySubject(PrivateKeyEntry.class, subject);
			for (PrivateKeyEntry privateKeyEntry : privateCaEntries) {
				X509CertificateHolder signerCertificate = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
				if (V3CertificateUtils.isSigingCertificate(signedCertificate, signerCertificate)){
					if(!signerCerts.contains(signerCertificate))signerCerts.add(signerCertificate);
					break signed;
				}
			}
			List<TrustedCertificateEntry> trusted = findCaEntriesBySubject(TrustedCertificateEntry.class, subject);
			for (TrustedCertificateEntry trustedCertificateEntry : trusted) {
				X509CertificateHolder signerCertificate = V3CertificateUtils.getX509CertificateHolder(trustedCertificateEntry.getTrustedCertificate());
				if (V3CertificateUtils.isSigingCertificate(signedCertificate, signerCertificate)){
					if(!signerCerts.contains(signerCertificate))signerCerts.add(signerCertificate);
					break signed;
				}
			}
		}
		if(signerCerts.isEmpty()) return Collections.emptySet();
		CertStore certStore = V3CertificateUtils.createCertStore(signerCerts);
		HashSet<CertStore> hashSet = new HashSet<CertStore>();
		hashSet.add(certStore);
		Set<CertStore> foundCertStores = findCertStores(signerCerts);
		if(foundCertStores!=null)hashSet.addAll(foundCertStores);
		return hashSet;
	}

	private <T extends Entry> List<T> findCaEntriesBySubject(Class<T> klass,
			X500Name... subjects) {
		List<KeyStoreAlias> keyStoreAliases = new ArrayList<KeyStoreAlias>();
		for (X500Name subject : subjects) {
			String endEntityIdHex = X500NameHelper
					.readUniqueIdentifier(subject);
			keyStoreAliases.add(new KeyStoreAlias(endEntityIdHex, null, null,
					null, null, KeyStoreAlias.PurposeEnum.CA, klass));
		}
		return findEntriesByAlias(klass, keyStoreAliases);
	}

	@Override
	public X509CRL getCrl() {
		return null;
	}

	private List<ContactListener> contactListeners = new ArrayList<ContactListener>();
	@Override
	public void addContactListener(ContactListener listener) {
		contactListeners.add(listener);
	}

	@Override
	public void removeContactListener(ContactListener listener) {
		contactListeners.remove(listener);
	}
}
