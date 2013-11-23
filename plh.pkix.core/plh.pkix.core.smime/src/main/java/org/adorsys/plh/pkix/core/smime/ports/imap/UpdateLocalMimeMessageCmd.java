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

import com.sun.mail.imap.AppendUID;

public class UpdateLocalMimeMessageCmd extends AbstractCommand {

	public UpdateLocalMimeMessageCmd(ActionContext commandContext) {
		super(commandContext);
	}

	public UpdateLocalMimeMessageCmd(String handle, ActionContext parentContext,
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

		FileWrapper localRootFolderDir = commandContext.get1(FileWrapper.class, StoragePort.LOCAL_FOLDER_ROOT);
		AppendUID appendUID = commandContext.get(AppendUID.class);
		String fileId = Utils.getHeader(mimeMessage, FileHandle.X_FID);
		if (StringUtils.isBlank(fileId))
			throw new IllegalStateException("Missing file id.");
		String folderLocation = Utils.getHeader(mimeMessage, FileHandle.X_LOC);
		List<String> folderPaths = PathComponentSplitter
				.toPathComponents(folderLocation);
		FileWrapper targetDir = localRootFolderDir;

		// First write file to the file system.
		if (!folderPaths.isEmpty()) {
			for (String folderName : folderPaths) {
				if (StringUtils.isBlank(folderName))
					continue;
				targetDir = targetDir.newChild(folderName);
			}
		}
		FileWrapper fileWrapper = targetDir.newChild(fileId);

		mimeMessage.addHeader(FileHandle.X_APPENDED, "" + new Date().getTime());

		String uid = "" + appendUID.uid;
		String uidv = "" + appendUID.uidvalidity;
		mimeMessage.addHeader(FileHandle.X_UID, uid);
		mimeMessage.addHeader(FileHandle.X_UIDV, uidv);
		OutputStream newOutputStream = fileWrapper.newOutputStream();
		mimeMessage.writeTo(newOutputStream);
		IOUtils.closeQuietly(newOutputStream);

		return Utils.getFileHandle(mimeMessage);
	}
}
