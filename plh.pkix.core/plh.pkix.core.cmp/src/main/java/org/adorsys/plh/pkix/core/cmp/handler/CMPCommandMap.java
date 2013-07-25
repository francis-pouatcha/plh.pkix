package org.adorsys.plh.pkix.core.cmp.handler;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;

public class CMPCommandMap {
	static {
		CommandMap.setDefaultCommandMap(addCommands(CommandMap
				.getDefaultCommandMap()));
	}

	private static MailcapCommandMap addCommands(CommandMap cm) {
		MailcapCommandMap mc = (MailcapCommandMap) cm;

		mc.addMailcap(CMPContentHandler.CMP_CONTENT_TYPE+";; x-java-content-handler="
				+ cmp_mime.class.getName());

		return mc;
	}

}
