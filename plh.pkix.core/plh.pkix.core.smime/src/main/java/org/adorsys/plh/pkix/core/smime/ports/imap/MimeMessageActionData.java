package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.store.TmpFileWraper;
import org.adorsys.plh.pkix.core.utils.action.ActionData;
import org.apache.commons.io.IOUtils;

/**
 * Holds {@link MimeMessage} object in an action context and helps serializes to and from the given stream.
 * 
 * @author fpo
 *
 */
public class MimeMessageActionData implements ActionData {
	
	private MimeMessage mimeMessage;
	private TmpFileWraper mimeMessageFile;
	
	
	public MimeMessageActionData(MimeMessage mimeMessage) {
		this.mimeMessage = mimeMessage;
	}

	public MimeMessageActionData() {
	}

	@Override
	public void writeTo(OutputStream outputStream) {

		try {
			if(mimeMessage!=null){
					mimeMessage.writeTo(outputStream);
			} else if (mimeMessageFile!=null){
				InputStream newInputStream = mimeMessageFile.newInputStream();
				IOUtils.copy(newInputStream, outputStream);
				IOUtils.closeQuietly(newInputStream);
			} else {
				throw new IllegalStateException("Either MimeMessage isntance or MimeMessage temporal file must be non null");
			}
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * ALlways read the mime message into a temporal file
	 */
	@Override
	public void readFrom(InputStream inputStream) {
		mimeMessageFile = new TmpFileWraper();
		OutputStream newOutputStream = mimeMessageFile.newOutputStream();
		try {
			IOUtils.copy(inputStream, newOutputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		IOUtils.closeQuietly(newOutputStream);
	}

	public MimeMessage getMimeMessage(Session session) {
		if(mimeMessage!=null) return mimeMessage;
		if(mimeMessageFile==null) throw new IllegalStateException("Missing mime message file.");
		InputStream newInputStream = mimeMessageFile.newInputStream();
		try {
			mimeMessage = new MimeMessage(session, newInputStream);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
		mimeMessageFile.dispose();
		mimeMessageFile = null;
		return mimeMessage;
	}
}
