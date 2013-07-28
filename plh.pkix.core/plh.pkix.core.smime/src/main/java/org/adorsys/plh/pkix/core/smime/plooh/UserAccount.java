package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias.PurposeEnum;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * 
 * @author fpo
 *
 */
public final class UserAccount {

	public static final String ACCOUNTS_FILE_NAME="accounts";	
	private final FilesContainer userAccountContainer;
	
	private final ActionContext accountContext;
	
	private final FileWrapper accountDirWrapper;

	
	public UserAccount(ActionContext accountContext, File accountDir, 
			FileWrapper accountDirWrapper, KeyStorePasswordsCallbackHandler callbackHandler) {
		userAccountContainer = FileContainerFactory.loadFilesContainer(accountDir, accountDirWrapper, callbackHandler);
		this.accountContext = accountContext;
		this.accountDirWrapper = accountDirWrapper;
		accountContext.put(UserAccount.class, this);
	}
	
	public UserAccount(ActionContext accountContext, File accountDir, 
			FileWrapper accountDirWrapper, 
			KeyStorePasswordsCallbackHandler callbackHandler,  X509CertificateHolder containingDeviceCertificate) {
		X500Name deviceSubjectDN = X500NameHelper.readSubjectDN(containingDeviceCertificate);
		String deviceCN = X500NameHelper.getAttributeString(deviceSubjectDN, BCStrictStyle.CN);
		userAccountContainer = FileContainerFactory.createFilesContainer(
				deviceCN, ContainerType.A,
				accountDir, accountDirWrapper, callbackHandler);
		this.accountContext = accountContext;
		this.accountDirWrapper = accountDirWrapper;
		accountContext.put(UserAccount.class, this);
	}

	public ContactManager getTrustedContactManager() {
		return userAccountContainer.getTrustedContactManager();
	}
	public ContactManager getPrivateContactManager() {
		return userAccountContainer.getPrivateContactManager();
	}

	public FileWrapper getAccountDir() {
		return accountDirWrapper;
	}

	public X509CertificateHolder getAccountCertificateHolder() {
		return userAccountContainer.getX509CertificateHolder();
	}
	
	public ActionContext getAccountContext() {
		return accountContext;
	}

	public void addContactListener(ContactListener contactListener) {
		userAccountContainer.getPrivateContactManager().addContactListener(contactListener);
		userAccountContainer.getTrustedContactManager().addContactListener(contactListener);
	}

	public List<PrivateKeyEntry> findAllMessagePrivateKeyEntriesByPublicKey(
			X509CertificateHolder certificateHolder) {
		ContactManager contactManager = userAccountContainer.getPrivateContactManager();
		List<KeyStoreAlias> allKas = contactManager.keyStoreAliases();
		List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias
				.selectByPublicKeyIdentifier(allKas,
						certificateHolder.getSubjectPublicKeyInfo(),
						PrivateKeyEntry.class);
		return contactManager.findEntriesByAlias(PrivateKeyEntry.class,
				keyStoreAliases);
	}
	
	public List<PrivateKeyEntry> findAllMessagePrivateKeyEntries(){
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(null, null,null, KeyStoreAlias.PurposeEnum.ME, PrivateKeyEntry.class);
		return userAccountContainer.getPrivateContactManager().findEntriesByAlias(PrivateKeyEntry.class, keyStoreAlias);
	}

	public PrivateKeyEntry getAnyMessagePrivateKeyEntry(){
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(null, null,null, KeyStoreAlias.PurposeEnum.ME, PrivateKeyEntry.class);
		return userAccountContainer.getPrivateContactManager().findEntriesByAlias(PrivateKeyEntry.class, keyStoreAlias).iterator().next();
	}

	public PrivateKeyEntry getAnyCaPrivateKeyEntry(){
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(null, null,null, KeyStoreAlias.PurposeEnum.CA, PrivateKeyEntry.class);
		return userAccountContainer.getPrivateContactManager().findEntriesByAlias(PrivateKeyEntry.class, keyStoreAlias).iterator().next();
	}
	
	public List<PrivateKeyEntry> findAllCaPrivateKeyEntries(){
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(null, null,null, KeyStoreAlias.PurposeEnum.CA, PrivateKeyEntry.class);
		return userAccountContainer.getPrivateContactManager().findEntriesByAlias(PrivateKeyEntry.class, keyStoreAlias);
	}
	
	public List<TrustedCertificateEntry> findContacts(X509CertificateHolder certificateHolder){
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(certificateHolder, TrustedCertificateEntry.class);
		return findContacts(keyStoreAlias);
	}
	
	public List<TrustedCertificateEntry> findContactsByPublicKey(String publicKeyIdHex){
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(publicKeyIdHex, null, null, PurposeEnum.ME, TrustedCertificateEntry.class);
		return findContacts(keyStoreAlias);
	}
	public List<TrustedCertificateEntry> findContacts(KeyStoreAlias keyStoreAlias){
		return userAccountContainer.getTrustedContactManager().findEntriesByAlias(TrustedCertificateEntry.class, keyStoreAlias);
	}
	public List<PrivateKeyEntry> findPrivateKeys(KeyStoreAlias keyStoreAlias){
		return userAccountContainer.getPrivateContactManager().findEntriesByAlias(PrivateKeyEntry.class, keyStoreAlias);
	}
}
