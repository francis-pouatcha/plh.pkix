package org.adorsys.plh.pkix.core.utils.contact;

import java.security.Key;
import java.security.KeyStore.Entry;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.bouncycastle.cert.X509CertificateHolder;

public interface ContactManager {

	//================================================================================//
	//		LISTENERS
	//================================================================================//
	public void addContactListener(ContactListener listener);
	public void removeContactListener(ContactListener listener);
	
	//================================================================================//
	//      MODIFICATION OPERATIONS
	//===============================================================================//
	public abstract void addCertEntry(X509CertificateHolder certHolder)
			throws PlhCheckedException;

	public abstract void addPrivateKeyEntry(Key key, Certificate[] chain)
			throws PlhCheckedException;

	public abstract void importIssuedCertificate(
			org.bouncycastle.asn1.x509.Certificate[] certArray)
			throws PlhCheckedException;

	//===============================================================================//
	// 		READ OPERATIONS
	//===============================================================================//
	public abstract <T extends Entry> T findEntryByAlias(Class<T> klass,
			List<KeyStoreAlias> keyStoreAliases);

	public abstract <T extends Entry> T findEntryByAlias(Class<T> klass,
			KeyStoreAlias... keyStoreAliases);

	public abstract <T extends Entry> List<T> findEntriesByAlias(
			Class<T> klass, List<KeyStoreAlias> keyStoreAliases);

	public abstract <T extends Entry> List<T> findEntriesByAlias(
			Class<T> klass, KeyStoreAlias... keyStoreAliases);

	public abstract List<KeyStoreAlias> keyStoreAliases();

	public abstract Set<TrustAnchor> getTrustAnchors();

	public abstract Set<CertStore> findCertStores(
			X509CertificateHolder... certificates);

	public abstract Set<CertStore> findCertStores(
			List<X509CertificateHolder> certificates);

	public abstract X509CRL getCrl();
	
//	public abstract PrivateKeyEntry getMainMessagePrivateKeyEntry();
//
//	public abstract PrivateKeyEntry getMainCaPrivateKeyEntry();
//
//	public abstract boolean login(char[] accountPass);
}