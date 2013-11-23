package org.adorsys.plh.pkix.core.smime.ports;

import java.io.IOException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.ports.imap.FileHandle;

/**
 * A storage port is used to store and retrieve data.
 * 
 * We use Application specific header fields to manage file information.
 * 
 * @author fpo
 *
 */
public interface StoragePort {
	
	/**
	 * The root folder from which to store messages on the local device.
	 */
	public static final String LOCAL_FOLDER_ROOT = "LOCAL_FOLDER_ROOT";
	
	/**
	 * Stores  the message. Returns a storage handle pointing to the location where the message is stored.
	 * @param mimeMessage
	 * @throws MessagingException 
	 * @throws IOException 
	 */
	public FileHandle store(MimeMessage mimeMessage) throws MessagingException, IOException;
	
	/**
	 * Loads a message passing the location of the message to the port.
	 * @param location
	 * @return
	 * @throws MessagingException 
	 */
	public MimeMessage load(FileHandle handle) throws MessagingException;
	
}
