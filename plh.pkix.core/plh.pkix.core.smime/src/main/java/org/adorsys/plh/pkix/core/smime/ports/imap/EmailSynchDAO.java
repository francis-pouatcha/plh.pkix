package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.DERGeneralizedTime;

/**
 * Reads and stores email account synch state in a file.
 * 
 * @author fpo
 * 
 */
public class EmailSynchDAO {

	/**
	 * The file in which account information are stored.
	 */
	private static final String ACCOUNT_SYNCH_FILENAME = "email_account_synch_data";

	private final EmailAccountConfig emailAccountConfig;

	private EmailSynchData emailSynchData;

	public EmailSynchDAO(EmailAccountConfig emailAccountConfig) throws IOException {
		assert emailAccountConfig==null:"EmailAccountConfig can not be null";
		this.emailAccountConfig = emailAccountConfig;
		if(this.emailSynchData==null) {
			EmailAccountData emailAccountData = emailAccountConfig.getEmailAccountDAO().getEmailAccountData();
			this.emailSynchData = new EmailSynchData(emailAccountData.getAccountId());
			Date startDate = emailAccountConfig.getUserAccount().getCreationDate();
			this.emailSynchData.setLastProcessedDate(new DERGeneralizedTime(startDate));
			save();
		}
		assert this.emailSynchData==null:"Missing email account synch file.";
	}
	
	public EmailSynchData getEmailSynchData() {
		return emailSynchData;
	}

	public EmailSynchDAO save() {
		if(emailSynchData==null) return this;
		FileWrapper file = emailAccountConfig.getEmailAccountDir().newChild(ACCOUNT_SYNCH_FILENAME);
		OutputStream newOutputStream = file.newOutputStream();
		try {
			IOUtils.write(emailSynchData.getEncoded(), newOutputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
		return this;
	}

	public EmailSynchDAO load() throws IOException {
		FileWrapper fileWrapper = emailAccountConfig.getEmailAccountDir().newChild(ACCOUNT_SYNCH_FILENAME);
		if (!fileWrapper.exists()) return this;
		InputStream newInputStream = fileWrapper.newInputStream();
		emailSynchData = EmailSynchData.getInstance(ASN1StreamUtils
				.readFrom(newInputStream));
		IOUtils.closeQuietly(newInputStream);
		return this;
	}
}
