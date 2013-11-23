package org.adorsys.plh.pkix.core.smime.ports.imap;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.AbstractCommand;
import org.adorsys.plh.pkix.core.utils.cmd.Command;

public class SmplPersistentCommand extends AbstractCommand {

	public SmplPersistentCommand(String handle, ActionContext commandContext) {
		super(handle, commandContext,null,null);
	}

	@Override
	public Command call() throws Exception {
		return this;
	}
}
