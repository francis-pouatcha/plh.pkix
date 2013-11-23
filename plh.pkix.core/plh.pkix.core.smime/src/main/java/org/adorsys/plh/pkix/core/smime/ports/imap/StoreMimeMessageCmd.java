package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.ports.StoragePort;
import org.adorsys.plh.pkix.core.smime.ports.utils.PathComponentSplitter;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.AbstractCommand;
import org.adorsys.plh.pkix.core.utils.cmd.Command;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * Persistent command fields are:
 * - The mimeMessage {@link MimeMessage}
 * - The targetDir {@link FileWrapper}
 * @author fpo
 *
 */
public class StoreMimeMessageCmd extends AbstractCommand {

	public StoreMimeMessageCmd(ActionContext commandContext) {
		super(commandContext);
	}

	public StoreMimeMessageCmd(String handle, ActionContext parentContext,
			MimeMessage mimeMessage) {
		super(handle, parentContext, null, null);
		commandContext.put(MimeMessageActionData.class, new MimeMessageActionData(mimeMessage));
	}

	@Override
	public Command call() throws Exception {
		FileHandle fileHandle = execute();
		commandContext.put(FileHandle.class, fileHandle);
		return this;
	}

	private FileHandle execute() throws MessagingException, IOException {
		IMapServer smtpImapServer = commandContext.get(IMapServer.class);
		if(smtpImapServer==null) 
			throw new IllegalStateException("Service of type " + IMapServer.class + " not available in the parent context.");
		MimeMessageActionData mimeMessageActionData = commandContext.get(MimeMessageActionData.class);
		if(mimeMessageActionData==null)
			throw new IllegalStateException("Missing mime message. The mime message to be stored must be in the command context.");

		MimeMessage mimeMessage = mimeMessageActionData.getMimeMessage(smtpImapServer.getSession());

		String fileId = Utils.getHeader(mimeMessage, FileHandle.X_FID);
		if(StringUtils.isBlank(fileId)) throw new IllegalStateException("The mime message to be stored must contain a haeder named: X-FID. This will be used as the name of the file in the file system.");
		
		String folderLocation = Utils.getHeader(mimeMessage, FileHandle.X_LOC);
		if(StringUtils.isBlank(folderLocation)) throw new IllegalStateException("The mime message to be stored must contain a haeder named: X_LOC. This is the path of the file in from the storage root directory.");

		FileWrapper localRootFolderDir = commandContext.get1(FileWrapper.class, StoragePort.LOCAL_FOLDER_ROOT);
		List<String> folderPaths = PathComponentSplitter.toPathComponents(folderLocation);
		
		// First write file to the file system.
		if(!folderPaths.isEmpty()){
			for (String folderName : folderPaths) {
				if(StringUtils.isBlank(folderName)) continue;
				localRootFolderDir = localRootFolderDir.newChild(folderName);
			}
		}
		
		FileWrapper mimeMessageFile = localRootFolderDir.newChild(fileId);
		mimeMessage.addHeader(FileHandle.X_STORED, ""+new Date().getTime());
		OutputStream newOutputStream = mimeMessageFile.newOutputStream();
		mimeMessage.writeTo(newOutputStream);
		IOUtils.closeQuietly(newOutputStream);
		return Utils.getFileHandle(mimeMessage);
	}
}
