package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Arrays;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.AbstractCommand;
import org.adorsys.plh.pkix.core.utils.cmd.Command;
import org.adorsys.plh.pkix.core.utils.cmd.CommandStore;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

/**
 * This is a storage for persistent command objects.
 * 
 * @author fpo
 *
 */
public class FileCommandStore implements CommandStore {

	private final FileWrapper commandStoreDir;
	private final ActionContext parentContext;

	public FileCommandStore(FileWrapper commandStoreDir, ActionContext commandContext) {
		this.commandStoreDir = commandStoreDir;
		this.parentContext = commandContext;
	}

	@Override
	public void storeCommand(Command command) {
		command.store(commandStoreDir);
	}

	@Override
	public Command loadCommand(String handle) {
		FileWrapper commandFile = commandStoreDir.newChild(handle);
		try {
			return AbstractCommand.load(commandFile, parentContext);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public void removeCommand(String handle) {
		FileWrapper commandFile = commandStoreDir.newChild(handle);
		commandFile.delete();
	}

	@Override
	public List<String> handles() {
		return Arrays.asList(commandStoreDir.list());
	}
}
