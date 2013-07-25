package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.File;

import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
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

}
