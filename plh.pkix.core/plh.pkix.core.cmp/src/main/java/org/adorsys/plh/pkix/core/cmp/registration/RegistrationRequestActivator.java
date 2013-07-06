package org.adorsys.plh.pkix.core.cmp.registration;

import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivator;
import org.adorsys.plh.pkix.core.cmp.activation.ModuleActivators;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class RegistrationRequestActivator extends ModuleActivator {

	public RegistrationRequestActivator(ActionContext accountContext,
			FileWrapper accountDir, ModuleActivators moduleActivators) {
		super(accountContext, accountDir, moduleActivators);
	}

	@Override
	protected void activate(ActionContext accountContext, FileWrapper accountDir) {
		accountContext.put(RegistrationRequestInitActionProcessor.class, new RegistrationRequestInitActionProcessor());
		accountContext.put(RegistrationRequestSendActionProcessor.class, new RegistrationRequestSendActionProcessor());		
	}

	@Override
	public ActionProcessor getIncommingProcessor() {
		return null;
	}

	@Override
	public Integer getIncomingMessageType() {
		return null;
	}
}
