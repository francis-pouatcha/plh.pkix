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
public class EmailSynchDAO {

	/**
	 * The file in which account information are stored.
	 */
	private static final String ACCOUNT_SYNCH_FILENAME = "account_synch";

	private final FileWrapper emailAccountDir;

	private EmailSynchData emailSynchData;

	public EmailSynchDAO(FileWrapper emailAccountDir) {
		super();
		this.emailAccountDir = emailAccountDir;
	}
	
	public EmailSynchData getEmailSynchData() {
		return emailSynchData;
	}

	public void setEmailSynchData(EmailSynchData emailSynchData) {
		this.emailSynchData = emailSynchData;
	}

	public void save() throws IOException {
		FileWrapper file = emailAccountDir.newChild(ACCOUNT_SYNCH_FILENAME);
		OutputStream newOutputStream = file.newOutputStream();
		try {
			IOUtils.write(emailSynchData.getEncoded(), newOutputStream);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
	}

	public void load() throws IOException {
		FileWrapper fileWrapper = emailAccountDir.newChild(ACCOUNT_SYNCH_FILENAME);
		if (!fileWrapper.exists())
			throw new IllegalStateException("Missing email account file.");
		InputStream newInputStream = fileWrapper.newInputStream();
		emailSynchData = EmailSynchData.getInstance(ASN1StreamUtils
				.readFrom(newInputStream));
		IOUtils.closeQuietly(newInputStream);
	}
}
