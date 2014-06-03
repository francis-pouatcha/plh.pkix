package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.mail.internet.ParseException;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.jboss.weld.exceptions.IllegalStateException;

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
	private static final String ACCOUNT_FILENAME = "email_account_data";

	private final EmailAccountConfig emailAccountConfig;
	
	private EmailAccountData emailAccountData;

	public EmailAccountDAO(EmailAccountConfig emailAccountConfig, EmailAccountData emailAccountData) throws IOException {
		this.emailAccountConfig = emailAccountConfig;
		if(emailAccountData!=null) {
			this.emailAccountData = emailAccountData;
			try {
				MailServerAddresses.getInstance().preprocessMailAccount(emailAccountData);
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
			save();
		} else {
			load();
		}
		assert this.emailAccountData==null:"Missing email account data file.";
	}
	
	public EmailAccountData getEmailAccountData() {
		return emailAccountData;
	}

	public EmailAccountDAO setEmailAccountData(EmailAccountData emailAccountData) {
		this.emailAccountData = emailAccountData;
		return this;
	}

	public EmailAccountDAO save() throws IOException {
		if(emailAccountData==null) return this;
		FileWrapper file = emailAccountConfig.getEmailAccountDir().newChild(ACCOUNT_FILENAME);
		OutputStream newOutputStream = file.newOutputStream();
		try {
			IOUtils.write(emailAccountData.getEncoded(), newOutputStream);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
		return this;
	}

	public EmailAccountDAO load() throws IOException {
		FileWrapper fileWrapper = emailAccountConfig.getEmailAccountDir().newChild(ACCOUNT_FILENAME);
		if (!fileWrapper.exists()) return this;
		InputStream newInputStream = fileWrapper.newInputStream();
		emailAccountData = EmailAccountData.getInstance(ASN1StreamUtils
				.readFrom(newInputStream));
		IOUtils.closeQuietly(newInputStream);
		return this;
	}
}
