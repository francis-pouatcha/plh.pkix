package org.adorsys.plh.pkix.core.utils.cmd;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.asn1.DERIA5StringActionData;
import org.bouncycastle.asn1.DERIA5String;

public class MailSendCmd extends AbstractCommand {
	private boolean called;
	
	
	public MailSendCmd(ActionContext commandContext) {
		super(commandContext);
	}

	public MailSendCmd(String handle, ActionContext commandContext, String message) {
		super(handle, commandContext, null, commandContext.get(MailServerAvailableCondition.class));
		commandContext.put(DERIA5StringActionData.class, new DERIA5StringActionData(new DERIA5String(message)));
	}

	@Override
	public Command call() throws Exception {
		called = true;
		MailServerSimulator simulator = commandContext.get(MailServerSimulator.class);
		DERIA5StringActionData deria5StringActionData = commandContext.get(DERIA5StringActionData.class);
		if(deria5StringActionData!=null){
			String message = deria5StringActionData.getDeria5String().getString();
			message = simulator.receiveMessage(message);
			commandContext.put(DERIA5StringActionData.class, new DERIA5StringActionData(new DERIA5String(message)));
		}
		return this;
	}

	public boolean isCalled() {
		return called;
	}
}
