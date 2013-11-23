package org.adorsys.plh.pkix.core.utils.cmd;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;


public class NullCommand extends AbstractCommand {

	public NullCommand(String handle) {
		super(handle, new ActionContext(), null,null);
	}

	@Override
	public Command call() throws Exception {
		return this;
	}

}
