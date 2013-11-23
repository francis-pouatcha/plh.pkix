package org.adorsys.plh.pkix.core.smime.ports.imap;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.CommandCondition;
import org.adorsys.plh.pkix.core.utils.cmd.ConditionMonitor;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerSimulator;

public class MailServerAvailableCondition implements CommandCondition {
	private final ActionContext commandContext;

	public MailServerAvailableCondition(ActionContext commandContext) {
		super();
		this.commandContext = commandContext;
		this.commandContext.put(MailServerAvailableCondition.class, this);
	}

	@Override
	public boolean favorable() {
		IMapServer iMapServer = commandContext.get(IMapServer.class);
		if(iMapServer==null) 
			throw new IllegalStateException("Service of type " + IMapServer.class + " not available in the parent context.");
		return iMapServer.isAvailable();
	}

	@Override
	public String getConditionId() {
		return MailServerAvailableCondition.class.getName();
	}

	@Override
	public ConditionMonitor getConditionMonitor() {
		return commandContext.get(MailServerAvailableConditionMonitor.class);
	}
}
