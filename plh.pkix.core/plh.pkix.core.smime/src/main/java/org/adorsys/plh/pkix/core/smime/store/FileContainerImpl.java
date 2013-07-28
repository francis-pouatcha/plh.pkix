package org.adorsys.plh.pkix.core.smime.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedDecryptorVerifier;
import org.adorsys.plh.pkix.core.smime.engines.CMSStreamedSignerEncryptor;
import org.adorsys.plh.pkix.core.smime.plooh.ContactManagerImpl;
import org.adorsys.plh.pkix.core.smime.utils.CloseSubstreamsOutputStream;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.cert.X509CertificateHolder;

public class FileContainerImpl implements FilesContainer {
	public static final String CONTAINER_CONTACTS_DIR_NAME="containerContacts";

	private final ContactManager trustedContactManager;
	
	private final PrivateKeyEntry containerPrivateKeyEntry;
	private final ContactManager privateContactManager;
	private final File rootDirectory;

	private final BuilderChecker checker = new BuilderChecker(FileContainerImpl.class);
	public FileContainerImpl(KeyStoreWraper containerKeyStoreWraper, File rootDirectory) {
		checker.checkNull(rootDirectory);
		this.rootDirectory = rootDirectory;
		this.rootDirectory.mkdirs();

		this.containerPrivateKeyEntry = containerKeyStoreWraper.getMainMessagePrivateKeyEntry();
		if(containerPrivateKeyEntry==null)throw new IllegalStateException("Container not authenticated.");
		this.privateContactManager = new ContactManagerImpl(containerKeyStoreWraper);
		
		FileWrapper containerContactDir = newRelativeFile(CONTAINER_CONTACTS_DIR_NAME);
		trustedContactManager = new ContactManagerImpl(containerContactDir);
		
		if(trustedContactManager.getContactCount()<=0){// new container.
			// add our ca self signed certificate to the contact manager.
			PrivateKeyEntry mainCaPrivateKey = containerKeyStoreWraper.getMainCaPrivateKey();
			X509CertificateHolder mainCaCertHolder = V3CertificateUtils.getX509CertificateHolder(mainCaPrivateKey.getCertificate());
			try {
				trustedContactManager.addCertEntry(mainCaCertHolder);
			} catch (PlhCheckedException e) {// not supposed to happen
				throw new IllegalStateException(e);
			}
		}
	}

	@Override
	public FileWrapper newRelativeFile(String fileRelativePath) {
		return new FileWraperImpl(fileRelativePath, rootDirectory, this);
	}

	@Override
	public FileWrapper newAbsoluteFile(String fileAbsolutePath) {
		File file = new File(fileAbsolutePath);
		return new FileWraperImpl(file.getName(), file.getParentFile(), this);
	}

	public CMSStreamedDecryptorVerifier newDecryptor(File file) {
		InputStream signedEncryptedInputStream;
		try {
			signedEncryptedInputStream = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
		return new CMSStreamedDecryptorVerifier()
			.withContactManager(privateContactManager)
			.withInputStream(signedEncryptedInputStream);
	}

	public OutputStream newOutputStream(File file) {
		if(!file.exists()) file.getParentFile().mkdirs();
		X509Certificate certificate = (X509Certificate) containerPrivateKeyEntry.getCertificate();
		FileOutputStream signedEncryptedOutputStream;
		try {
			signedEncryptedOutputStream = new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);
		}
		OutputStream signingEncryptingOutputStream = new CMSStreamedSignerEncryptor()
		.withRecipientCertificates(Arrays.asList(certificate))
		.withOutputStream(signedEncryptedOutputStream)
		.signingEncryptingOutputStream(containerPrivateKeyEntry);
		CloseSubstreamsOutputStream closeSubstreamsOutputStream = new CloseSubstreamsOutputStream(signingEncryptingOutputStream);
		closeSubstreamsOutputStream.addSubStream(signedEncryptedOutputStream);
		return closeSubstreamsOutputStream;
	}

	@Override
	public String getPublicKeyIdentifier() {
		X509CertificateHolder certHldr = V3CertificateUtils.getX509CertificateHolder(containerPrivateKeyEntry.getCertificate());
		return KeyIdUtils.createPublicKeyIdentifierAsString(certHldr);
	}

	@Override
	public X509CertificateHolder getX509CertificateHolder() {
		return V3CertificateUtils.getX509CertificateHolder(containerPrivateKeyEntry.getCertificate());
	}

	@Override
	public ContactManager getTrustedContactManager() {
		return trustedContactManager;
	}

	@Override
	public ContactManager getPrivateContactManager() {
		return privateContactManager;
	}
}
