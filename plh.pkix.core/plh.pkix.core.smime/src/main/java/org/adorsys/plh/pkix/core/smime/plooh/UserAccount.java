package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.adorsys.plh.pkix.core.smime.ports.CommunicationPort;
import org.adorsys.plh.pkix.core.smime.ports.StoragePort;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias.PurposeEnum;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
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
	
	private CommunicationPort systemComPort;
	private CommunicationPort dataComPort;
	
	private StoragePort dataStoragePort;
	
	public UserAccount(ActionContext accountContext, File accountDir, 
			FileWrapper accountDirWrapper, CallbackHandler callbackHandler) {
		userAccountContainer = FileContainerFactory.loadFilesContainer(accountDir, accountDirWrapper, callbackHandler);
		this.accountContext = accountContext;
		this.accountDirWrapper = accountDirWrapper;
		accountContext.put(UserAccount.class, this);
	}
	
	public UserAccount(ActionContext accountContext, File accountDir, 
			FileWrapper accountDirWrapper, 
			CallbackHandler callbackHandler,  
			X509CertificateHolder containingDeviceCertificate) {
//		X500Name deviceSubjectDN = X500NameHelper.readSubjectDN(containingDeviceCertificate);
//		String deviceCN = X500NameHelper.getAttributeString(deviceSubjectDN, BCStrictStyle.CN);
		userAccountContainer = FileContainerFactory.createFilesContainer(
				ContainerType.A,
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

	public CommunicationPort getSystemComPort() {
		return systemComPort;
	}

	public void setSystemComPort(CommunicationPort systemComPort) {
		this.systemComPort = systemComPort;
	}

	public CommunicationPort getDataComPort() {
		return dataComPort;
	}

	public void setDataComPort(CommunicationPort dataComPort) {
		this.dataComPort = dataComPort;
	}

	public StoragePort getDataStoragePort() {
		return dataStoragePort;
	}

	public void setDataStoragePort(StoragePort dataStoragePort) {
		this.dataStoragePort = dataStoragePort;
	}
	
	/**
	 * Returns the 
	 * @return
	 */
	public Date getCreationDate(){
		List<PrivateKeyEntry> findAllCaPrivateKeyEntries = findAllCaPrivateKeyEntries();
		Date result = null;
		for (PrivateKeyEntry privateKeyEntry : findAllCaPrivateKeyEntries) {
			Certificate certificate = privateKeyEntry.getCertificate();
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
			Date before = certificateHolder.getNotBefore();
			if(result==null) {
				result = before;
			} else if(before!=null){
				result = result.before(before)?result:before;
			}
		}
		return result;
	}
}
