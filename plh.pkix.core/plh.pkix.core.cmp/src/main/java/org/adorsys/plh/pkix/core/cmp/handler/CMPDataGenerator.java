package org.adorsys.plh.pkix.core.cmp.handler;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.asn1.cmp.PKIMessage;

public class CMPDataGenerator extends CMPCommandMap{

	public MimeBodyPart generate(PKIMessage pkiMessage)
			throws MessagingException {
		
        MimeBodyPart data = new MimeBodyPart();

        String filename = PKIMessageTypeString.get(pkiMessage);
        data.setContent(pkiMessage, CMPContentHandler.CMP_CONTENT_TYPE);
        data.addHeader("Content-Type", CMPContentHandler.CMP_CONTENT_TYPE);
        data.addHeader("Content-Disposition", "attachment; filename=\""+filename+".cmp\"");
        data.addHeader("Content-Description", CMPContentHandler.CMP_CONTENT_DESCRIPTION);
        data.addHeader("Content-Transfer-Encoding", CMPContentHandler.CMP_CONTENT_TRANSFER_ENCODING);
//        data.setContentID("CMP MESSAGE " + System.currentTimeMillis());
        return data;
	}

}
