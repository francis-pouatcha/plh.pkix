package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;

public class MessageUtils {

	public static void writeMessageTo(MimeMessage mimeMessage,
			FileWrapper messageFile) {
		OutputStream outputStream = messageFile.newOutputStream();
		try {
			mimeMessage.writeTo(outputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
		IOUtils.closeQuietly(outputStream);
	}

	public static MimeMessage readMessageFrom(FileWrapper messageFile,
			Session session) {
		try {
			return new WrappedMimeMessage(session, messageFile);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
	}

	public static void documentSent(DERIA5String messageId,
			FileWrapper msgSentDirectory) {
		DERGeneralizedTime sent = new DERGeneralizedTime(new Date());
		SMTPSentMessageData sentMessageData = new SMTPSentMessageData(
				messageId, sent);
		FileWrapper sentMessageFileName = msgSentDirectory.newChild(messageId
				.getString());
		OutputStream newOutputStream = sentMessageFileName.newOutputStream();
		try {
			IOUtils.write(sentMessageData.getEncoded(), newOutputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
	}

	public static void documentError(DERIA5String messageId,
			MessagingException mex, FileWrapper msgErrorDirectory) {
		DERGeneralizedTime sent = new DERGeneralizedTime(new Date());
		SMTPSentMessageData sentMessageData = new SMTPSentMessageData(
				messageId, sent);
		sentMessageData.setErrorMessgae(new DERIA5String(mex.getMessage()));
		sentMessageData.setStatus(new DERIA5String(mex.getClass()
				.getSimpleName()));
		FileWrapper sentMessageFileName = msgErrorDirectory.newChild(messageId
				.getString());
		OutputStream newOutputStream = sentMessageFileName.newOutputStream();
		try {
			IOUtils.write(sentMessageData.getEncoded(), newOutputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
	}

	public static SMTPSentMessageData readSentMessage(String messageId,
			FileWrapper msgSentDirectory) throws IOException {
		FileWrapper sentMessageFile = msgSentDirectory.newChild(messageId);
		if (!sentMessageFile.exists())
			return null;
		InputStream newInputStream = sentMessageFile.newInputStream();
		try {
			SMTPSentMessageData sentMessageData = SMTPSentMessageData
					.getInstance(ASN1StreamUtils.readFrom(newInputStream));
			return sentMessageData;
		} finally {
			IOUtils.closeQuietly(newInputStream);
		}
	}

	public static String getHeader(MimeMessage mimeMessage, String name) {
		String[] headerValues;
		try {
			headerValues = mimeMessage.getHeader(name);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
		if (headerValues == null || headerValues.length == 0) {
			throw new IllegalArgumentException("Missing header information "
					+ name);
		}
		return headerValues[0];
	}

	public static FileHandle getFileHandle(MimeMessage mimeMessage) {
		return new FileHandle()
				.setFid(getHeader(mimeMessage, FileHandle.X_FID))
				.setLoc(getHeader(mimeMessage, FileHandle.X_LOC))
				.setPath(getHeader(mimeMessage, FileHandle.X_PATH))
				.setUid(getHeader(mimeMessage, FileHandle.X_UID))
				.setUiddValidity(getHeader(mimeMessage, FileHandle.X_UIDV))
				.setAppended(getHeader(mimeMessage, FileHandle.X_APPENDED))
				.setStored(getHeader(mimeMessage, FileHandle.X_STORED));
	}

	public static Date getDate(String propertyName, MimeMessage mimeMessage)
			throws MessagingException {
		String[] header = mimeMessage.getHeader(propertyName);
		if (header == null || header.length <= 0)
			return null;
		String dateString = header[header.length - 1];
		try {
			return new Date(Long.valueOf(dateString));
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

	public static void documentReceivedOk(String messageId,Long messageUid,Long uidValidity,
			FileWrapper msgProcDirectory) {
		DERGeneralizedTime received = new DERGeneralizedTime(new Date());
		IMapReceivedMessageData receivedMessageData = new IMapReceivedMessageData(new DERIA5String(messageId), new DERInteger(messageUid), new DERInteger(uidValidity), received);
		FileWrapper receivedMessageFile = msgProcDirectory.newChild(messageId);
		OutputStream newOutputStream = receivedMessageFile.newOutputStream();
		try {
			IOUtils.write(receivedMessageData.getEncoded(), newOutputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
	}
	
	public static void documentReceivedFailled(String messageId,Long messageUid,Long uidValidity,
			FileWrapper msgProcDirectory, Exception pex) {
		DERGeneralizedTime received = new DERGeneralizedTime(new Date());
		IMapReceivedMessageData receivedMessageData = new IMapReceivedMessageData(new DERIA5String(messageId), new DERInteger(messageUid), new DERInteger(uidValidity), received);
		receivedMessageData.setErrorMessgae(new DERIA5String(pex.getMessage()));
		receivedMessageData.setStatus(new DERIA5String(pex.getClass()
				.getSimpleName()));
		FileWrapper receivedMessageFile = msgProcDirectory.newChild(messageId);
		OutputStream newOutputStream = receivedMessageFile.newOutputStream();
		try {
			IOUtils.write(receivedMessageData.getEncoded(), newOutputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(newOutputStream);
		}
	}
	
	public static IMapReceivedMessageData readReceivedMessage(String messageId,
			FileWrapper msgProcDirectory) throws IOException {
		FileWrapper receivedMessageFile = msgProcDirectory.newChild(messageId);
		if (!receivedMessageFile.exists())
			return null;
		InputStream newInputStream = receivedMessageFile.newInputStream();
		try {
			return IMapReceivedMessageData
					.getInstance(ASN1StreamUtils.readFrom(newInputStream));
		} finally {
			IOUtils.closeQuietly(newInputStream);
		}
	}
	
}
