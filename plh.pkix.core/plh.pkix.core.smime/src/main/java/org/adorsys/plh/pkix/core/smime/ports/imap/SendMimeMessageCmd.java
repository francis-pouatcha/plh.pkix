package org.adorsys.plh.pkix.core.smime.ports.imap;

import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.AbstractCommand;
import org.adorsys.plh.pkix.core.utils.cmd.Command;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerAvailableCondition;

public class SendMimeMessageCmd extends AbstractCommand {

	public SendMimeMessageCmd(ActionContext commandContext) {
		super(commandContext);
	}

	public SendMimeMessageCmd(String handle, ActionContext parentContext,
			MimeMessage mimeMessage) {
		super(handle, parentContext, null, parentContext.get(MailServerAvailableCondition.class));
		if(getCondition()==null) 
			throw new IllegalStateException("Service of type " + MailServerAvailableCondition.class + " not available in the parent context.");
		commandContext.put(MimeMessageActionData.class, new MimeMessageActionData(mimeMessage));
	}

	@Override
	public Command call() throws Exception {
		IMapServer iMapServer = commandContext.get(IMapServer.class);
		if(iMapServer==null) 
			throw new IllegalStateException("Service of type " + IMapServer.class + " not available in the parent context.");
		MimeMessageActionData mimeMessageActionData = commandContext.get(MimeMessageActionData.class);
		if(mimeMessageActionData!=null){
			MimeMessage mimeMessage = mimeMessageActionData.getMimeMessage(iMapServer.getSession());
			iMapServer.sendMessage(mimeMessage);
		}
		return this;
	}

}
