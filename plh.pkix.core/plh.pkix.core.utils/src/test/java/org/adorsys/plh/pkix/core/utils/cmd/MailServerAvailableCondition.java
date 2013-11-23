package org.adorsys.plh.pkix.core.utils.cmd;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class MailServerAvailableCondition implements CommandCondition {
	private final ActionContext commandContext;

	public MailServerAvailableCondition(ActionContext commandContext) {
		super();
		this.commandContext = commandContext;
		this.commandContext.put(MailServerAvailableCondition.class, this);
	}

	@Override
	public boolean favorable() {
		MailServerSimulator mailServerSimulator = commandContext.get(MailServerSimulator.class);
		return mailServerSimulator.isAvailable();
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
