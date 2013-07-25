package org.adorsys.plh.pkix.core.cmp.handler;

import java.io.IOException;

import javax.mail.BodyPart;
import javax.mail.MessagingException;

import org.bouncycastle.asn1.cmp.PKIMessage;

public class CMPDataParser extends CMPCommandMap{

	public PKIMessage parse(BodyPart bodyPart) throws IOException, MessagingException{
		return (PKIMessage) bodyPart.getContent();
	}
}
