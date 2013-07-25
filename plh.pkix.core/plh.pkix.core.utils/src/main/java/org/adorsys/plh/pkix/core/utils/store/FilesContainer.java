package org.adorsys.plh.pkix.core.utils.store;

import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Provides access to a directory and it sub-directories. Generally a file container
 * will hold the secret need to access keys used to encrypt directory data.
 * 
 * The file container is always associated with a directory on the file system.
 * 
 * @author francis
 *
 */
public interface FilesContainer {

	/**
	 * Returns a {@link FileWrapper} that can read and/or write the file referenced
	 * with fileRelativePath.
	 * 
	 * @param fileRelativePath
	 * @return
	 */
	public FileWrapper newRelativeFile(String fileRelativePath);

	/**
	 * Returns a {@link FileWrapper} that can read and/or write the file referenced
	 * with fileRelativePath.
	 * 
	 * @param fileAbsolutePath
	 * @return
	 */
	public FileWrapper newAbsoluteFile(String fileAbsolutePath);
	
	/**
	 * Returns the public key identifier of the key pair used to 
	 * encrypt files in this container.
	 * 
	 * @return
	 */
	public String getPublicKeyIdentifier();

	/**
	 * Returns the certificate holder of this container.
	 * @return
	 */
	public X509CertificateHolder getX509CertificateHolder();

	/**
	 * Returns the contact manager associated with this container.
	 * @return
	 */
	public ContactManager getTrustedContactManager();
	public ContactManager getPrivateContactManager();
}
