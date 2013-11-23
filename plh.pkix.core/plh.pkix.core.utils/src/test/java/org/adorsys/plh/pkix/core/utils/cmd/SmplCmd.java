package org.adorsys.plh.pkix.core.utils.cmd;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class SmplCmd extends AbstractCommand {

	public SmplCmd(String handle, ActionContext commandContext) {
		super(handle, commandContext,null,null);
	}

	@Override
	public Command call() throws Exception {
		return null;
	}

}
