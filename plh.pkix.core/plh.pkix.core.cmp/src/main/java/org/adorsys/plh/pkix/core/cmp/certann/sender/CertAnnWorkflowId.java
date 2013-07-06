package org.adorsys.plh.pkix.core.cmp.certann.sender;

import java.math.BigInteger;

public class CertAnnWorkflowId {

	public static String getWorkflowId(BigInteger announcingCertSerial, BigInteger receiverCertSerial){
		return new StringBuilder()
			.append(announcingCertSerial.toString(16).toLowerCase())
			.append("_")
			.append(receiverCertSerial.toString(16).toLowerCase()).toString();
	}
}
