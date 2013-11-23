package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.util.Date;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.AbstractCommand;
import org.adorsys.plh.pkix.core.utils.cmd.Command;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerAvailableCondition;

import com.sun.mail.imap.AppendUID;
import com.sun.mail.imap.IMAPFolder;

public class StoreRemoteMimeMessageCmd  extends AbstractCommand {
	/**
	 * The name of the imap folder.
	 */
	public static final String X_CMD_IMAP_FOLDER_NAME = "X-CMD_IMAP_FOLDER_NAME"; 

	public StoreRemoteMimeMessageCmd(ActionContext commandContext) {
		super(commandContext);
	}

	public StoreRemoteMimeMessageCmd(String handle, ActionContext parentContext,
			MimeMessage mimeMessage) {
		super(handle, parentContext, null, parentContext.get(MailServerAvailableCondition.class));
		if(getCondition()==null) 
			throw new IllegalStateException("Service of type " + MailServerAvailableCondition.class + " not available in the parent context.");
		commandContext.put(MimeMessageActionData.class, new MimeMessageActionData(mimeMessage));
	}

	public AppendUID execute() throws MessagingException, IOException {
		IMapServer smtpImapServer = commandContext.get(IMapServer.class);
		if(smtpImapServer==null) 
			throw new IllegalStateException("Service of type " + IMapServer.class + " not available in the parent context.");
		MimeMessageActionData mimeMessageActionData = commandContext.get(MimeMessageActionData.class);
		if(mimeMessageActionData!=null){
			MimeMessage mimeMessage = mimeMessageActionData.getMimeMessage(smtpImapServer.getSession());
			smtpImapServer.sendMessage(mimeMessage);
		}

		
		
		IMAPFolder storageFolder = commandContext.get(IMAPFolder.class);
		MimeMessage mimeMessage = commandContext.get(MimeMessage.class);

		String[] uid = mimeMessage.getHeader(FileHandle.X_UID);
		
		MimeMessage existingMessage = null;
		if(uid!=null && uid.length>0){
			Long uidLong = Long.valueOf(uid[uid.length-1]);
			existingMessage = (MimeMessage) storageFolder.getMessageByUID(uidLong);
		}
	
		boolean updateMimeMessage = true;
		if(existingMessage!=null){
			Date appended = Utils.getDate(FileHandle.X_APPENDED, existingMessage);
			if(appended!=null){
				Date stored = Utils.getDate(FileHandle.X_STORED, mimeMessage);
				if(stored==null || stored.before(appended)){
					updateMimeMessage = false;
				}
			}

		}
		if(updateMimeMessage){
			mimeMessage.addHeader(FileHandle.X_APPENDED, ""+new Date().getTime());
			AppendUID[] appendUIDMessages = storageFolder.appendUIDMessages(new Message[]{mimeMessage});
			return appendUIDMessages[0];
		} else {
			return null;
		}		
	}

	@Override
	public Command call() throws Exception {
		AppendUID appendUID = execute();
		commandContext.put(AppendUID.class, appendUID);
		return this;
	}
//
//	@Override
//	public void internalStore(FileWrapper commandDir) throws IOException, MessagingException {
//		MimeMessage mimeMessage = commandContext.get(MimeMessage.class);
//		if(mimeMessage!=null){
//			IMAPFolder rootFolder = commandContext.get(IMAPFolder.class);
//			if(rootFolder!=null){
//				String fullName = rootFolder.getFullName();
//				mimeMessage.addHeader(X_CMD_IMAP_FOLDER_NAME, fullName);
//			}
//			storeMimeMessage(commandDir, mimeMessage);
//		}
//	}

}
