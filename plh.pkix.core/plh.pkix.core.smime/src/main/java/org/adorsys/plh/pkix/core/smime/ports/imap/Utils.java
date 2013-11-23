package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Date;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

public final class Utils {

	public static String getHeader(MimeMessage mimeMessage, String name){
		String[] headerValues;
		try {
			headerValues = mimeMessage.getHeader(name);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
		if(headerValues==null || headerValues.length==0){
			throw new IllegalArgumentException("Missing header information " + name);
		}
		return headerValues[0];
	}
	
	public static FileHandle getFileHandle(MimeMessage mimeMessage){
		return new FileHandle()
			.setFid(getHeader(mimeMessage, FileHandle.X_FID))
			.setLoc(getHeader(mimeMessage, FileHandle.X_LOC))
			.setPath(getHeader(mimeMessage, FileHandle.X_PATH))
			.setUid(getHeader(mimeMessage, FileHandle.X_UID))
			.setUiddValidity(getHeader(mimeMessage, FileHandle.X_UIDV))
			.setAppended(getHeader(mimeMessage, FileHandle.X_APPENDED))
			.setStored(getHeader(mimeMessage, FileHandle.X_STORED));
	}

	public static Date getDate(String propertyName, MimeMessage mimeMessage) throws MessagingException{
		String[] header = mimeMessage.getHeader(propertyName);
		if(header==null || header.length<=0) return null;
		String dateString = header[header.length-1];
		try {
			return new Date (Long.valueOf(dateString));
		} catch (Exception ex){
			ex.printStackTrace();
			return null;
		}
	}

}
