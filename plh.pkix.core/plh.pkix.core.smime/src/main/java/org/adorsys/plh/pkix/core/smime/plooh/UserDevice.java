package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;

import org.adorsys.plh.pkix.core.smime.ports.CommunicationPort;
import org.adorsys.plh.pkix.core.smime.ports.StoragePort;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.DelegatingKeyStoreCallbackHandler;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Represents a plooh installation on a user account on a computer.
 * 
 * <h1>Plooh User Home Directory</h1>
 * 
 * The plooh user home directory is the location used to manage a <b>plooh user device</b>.
 * 
 * <h3>Locating the plooh user home directory</h3>
 * 
 * The plooh user home directory is the ${plooh.user.home.dir} returned by the jvm. In order to test plooh in 
 * the maven /target directory, this property can be by set prior to loading the test class. In the case of junit in the 
 * @BeforeClass annotated method.
 * 
 * If the system property ${plooh.user.home.dir} is not set, the application will look for the system property
 * ${user.home} and append a .plooh sub directory on it.
 * 
 * <h3>Protecting the plooh user home directory</h3>
 * 
 * The plooh user home directory can be protected using a secret question whose answer is used to encrypt the 
 * user directory's bootstraping information. This can be done by providing the corresponding call back handler.
 * 
 * @author fpo
 *
 */
public final class UserDevice {

	public static final String PLOOH_DEFAULT_USER_HOME_DIR_NAME = ".plooh";
	public static final String PROPERTY_KEY_USER_HOME = "user.home";
	public static final String PROPERTY_KEY_PLOOH_USER_HOME_DIR = "plooh.user.home.dir";
//	public static final String PROPERTY_KEY_USER_NAME="user.name";
	public static final String ACCOUNTS_FILE_NAME="accounts";	
	
	private final FilesContainer userDeviceContainer;
	private final List<X509CertificateHolder> accounts;
	
	private CommunicationPort communicationPort;
	
	private StoragePort storagePort;
	
	/**
	 * Instantiates the plooh application on a computer's user account.
	 * 
	 * @param containerKeyPass
	 * @param containerStorePass
	 */
	public UserDevice(CallbackHandler callbackHandler, Properties properties) {
		
		File ploohUserHomeDirDiscovered = discoverPloohUserHomeDirectory(properties);
		
		if(ploohUserHomeDirDiscovered.exists()){
			userDeviceContainer = FileContainerFactory.loadFilesContainer(ploohUserHomeDirDiscovered, null, callbackHandler);
			
		} else {
			userDeviceContainer = FileContainerFactory.createFilesContainer(ContainerType.D,
					ploohUserHomeDirDiscovered, null, callbackHandler);
		}
		accounts = load();// load registered accounts
	}
	
	private File discoverPloohUserHomeDirectory(Properties properties){
		String ploohUserHomeDirPath = properties.getProperty(PROPERTY_KEY_PLOOH_USER_HOME_DIR);
		if(ploohUserHomeDirPath==null){
			String userHomeDirPath = properties.getProperty(PROPERTY_KEY_USER_HOME);
			File userHomeDir = new File(userHomeDirPath);
			return new File(userHomeDir, PLOOH_DEFAULT_USER_HOME_DIR_NAME);
		} else {
			return new File(ploohUserHomeDirPath);
		}
	}
	
	/**
	 * Create a user account. Following conditions must apply:
	 * - The account directory path must either non existent or empty.
	 * @param accountDir
	 * @return
	 * @throws SelectedFileNotADirectoryException 
	 * @throws SelectedDirNotEmptyException 
	 */
	public UserAccount createUserAccount(File accountDir, CallbackHandler callbackHandler) throws SelectedFileNotADirectoryException{
		
		FileWrapper accountDirWrapper = userDeviceContainer.newAbsoluteFile(accountDir.getAbsolutePath());
		CallbackHandler delegatingCallbackHandler = newDelegatingCallbackHandler(accountDirWrapper, callbackHandler);
		
		UserAccount userAccount = null;
		if(accountDir.exists()){
			userAccount = new UserAccount(new ActionContext(), accountDir, accountDirWrapper, delegatingCallbackHandler);
		} else {
			X509CertificateHolder deviceCertificateHolder = userDeviceContainer.getX509CertificateHolder();
			userAccount = new UserAccount(new ActionContext(), accountDir, accountDirWrapper, delegatingCallbackHandler, deviceCertificateHolder);
			X509CertificateHolder accountCertificateHolder = userAccount.getAccountCertificateHolder();
			try {
				userDeviceContainer.getTrustedContactManager().addCertEntry(accountCertificateHolder);
			} catch (PlhCheckedException e) {
				throw new IllegalStateException(e);
			}
		}
		return userAccount;
	}

	/**
	 * Loads all accounts managed by this instance and display them to the user for selection.
	 */
	private List<X509CertificateHolder> load() {
		ContactManager contactManager = userDeviceContainer.getTrustedContactManager();
		List<KeyStoreAlias> keyStoreAliases = contactManager.keyStoreAliases();
		List<TrustedCertificateEntry> accountEntries = contactManager.findEntriesByAlias(TrustedCertificateEntry.class, keyStoreAliases);
		List<X509CertificateHolder> result = new ArrayList<X509CertificateHolder>();
		for (TrustedCertificateEntry trustedCertificateEntry : accountEntries) {
			// This certificate is issued by the account owner and signed by the 
			Certificate accountDetails = trustedCertificateEntry.getTrustedCertificate();
			X509CertificateHolder accountCertHolder = V3CertificateUtils.getX509CertificateHolder(accountDetails);
			X500Name subjectDN = X500NameHelper.readSubjectDN(accountCertHolder);
			String attributeString = X500NameHelper.getAttributeString(subjectDN, BCStyle.T);
			if(ContainerType.A.name().equals(attributeString)){
				result.add(accountCertHolder);
			}
		}
		return result;
	}

	public List<X509CertificateHolder> getAccounts() {
		return accounts;
	}

	public UserAccount loadUserAccount(X509CertificateHolder accountCertificateHolder, CallbackHandler callbackHandler) throws SelectedFileNotADirectoryException{
		List<String> uris = X500NameHelper.readSubjectURIsFromAltName(accountCertificateHolder);
		String accountDirURI =null;
		for (String string : uris) {
			if(string.startsWith("file")) {
				accountDirURI=string;
				break;
			}
		}
		if(accountDirURI==null) throw new IllegalStateException("Missing account directory");
		File accountDir;
		try {
			accountDir = FileUtils.toFile(new URI(accountDirURI).toURL());
		} catch (MalformedURLException e) {
			throw new IllegalStateException(e);
		} catch (URISyntaxException e) {
			throw new IllegalStateException(e);
		}
		if(!accountDir.exists())
			throw new IllegalStateException("Missing account directory");
		return createUserAccount(accountDir,callbackHandler);
	}

	public CommunicationPort getCommunicationPort() {
		return communicationPort;
	}

	public void setCommunicationPort(CommunicationPort communicationPort) {
		this.communicationPort = communicationPort;
	}

	public StoragePort getStoragePort() {
		return storagePort;
	}

	public void setStoragePort(StoragePort storagePort) {
		this.storagePort = storagePort;
	}
	
	private CallbackHandler newDelegatingCallbackHandler(FileWrapper accountDirWrapper, CallbackHandler callbackHandler){
		// Generate a password
		FileWrapper keyPassFileWrapper = accountDirWrapper.newChild("keyPass");
		FileWrapper storePassFileWrapper = accountDirWrapper.newChild("storePass");
		
		char[] keyPass = null;
		char[] storePass = null;
		if(keyPassFileWrapper.exists()){
			InputStream inputStream = keyPassFileWrapper.newInputStream();
			try {
				keyPass = IOUtils.toCharArray(inputStream);
				inputStream.close();
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}

		if(storePassFileWrapper.exists()){
			InputStream inputStream = storePassFileWrapper.newInputStream();
			try {
				storePass = IOUtils.toCharArray(inputStream);
				inputStream.close();
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}

		return new DelegatingKeyStoreCallbackHandler(keyPass, storePass, callbackHandler);
	}
}
