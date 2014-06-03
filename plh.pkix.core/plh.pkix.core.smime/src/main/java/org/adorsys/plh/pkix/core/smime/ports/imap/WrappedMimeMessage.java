package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.mail.Flags;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.SharedInputStream;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

/**
 * Implements the functionality of a mime message that has been temporarily
 * stored to the file system maybe because the mail server was temporarily not
 * available or maybe because the local machine is not connected to the
 * internet.
 * 
 * We can not use the JavaMail SharedInputStream because the underlying
 * information is not directly available thru a file, but read from an encrypted
 * stream.
 * 
 * @author francis
 * 
 */
public class WrappedMimeMessage extends MimeMessage {

	/**
	 * The underlying encrypted file.
	 */
	private FileWrapper fileWrapper;
	
	public WrappedMimeMessage(Session session, FileWrapper fileWrapper)
			throws MessagingException {
		super(session);
		assert session!=null : "session can not be null";
		flags = new Flags(); // empty Flags object
		InputStream is = fileWrapper.newInputStream();
		if (!(is instanceof ByteArrayInputStream)
				&& !(is instanceof BufferedInputStream)
				&& !(is instanceof SharedInputStream))
			is = new BufferedInputStream(is);

		headers = createInternetHeaders(is);

		modified = false;
		saved = true;
	}

	@Override
	protected InputStream getContentStream() throws MessagingException {
		InputStream is = fileWrapper.newInputStream();
		// read header information.
		new InternetHeaders(is);
		// return stream marked at start of the body
		return is;
	}
}
