package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;

/**
 * Reads and stores email account data in a file.
 * 
 * @author fpo
 * 
 */
public class EmailAccountDAO {

	/**
	 * The file in which account information are stored.
	 */
	private static final String ACCOUNT_FILENAME = "account";

	private final FileWrapper emailAccountDir;

	private EmailAccountData emailAccountData;

	public EmailAccountDAO(FileWrapper emailAccountDir) {
		super();
		this.emailAccountDir = emailAccountDir;
	}
	
	public EmailAccountData getEmailAccountData() {
		return emailAccountData;
	}

	public void setEmailAccountData(EmailAccountData emailAccountData) {
		this.emailAccountData = emailAccountData;
	}

	public void save() throws IOException {
		FileWrapper file = emailAccountDir.newChild(ACCOUNT_FILENAME);
		OutputStream newOutputStream = file.newOutputStream();
		try {
			IOUtils.write(emailAccountData.getEncoded(), newOutputStream);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
	}

	public void load() throws IOException {
		FileWrapper fileWrapper = emailAccountDir.newChild(ACCOUNT_FILENAME);
		if (!fileWrapper.exists())
			throw new IllegalStateException("Missing email account file.");
		InputStream newInputStream = fileWrapper.newInputStream();
		emailAccountData = EmailAccountData.getInstance(ASN1StreamUtils
				.readFrom(newInputStream));
		IOUtils.closeQuietly(newInputStream);
	}
}
