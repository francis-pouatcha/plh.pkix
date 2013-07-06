package org.adorsys.plh.pkix.core.cmp.stores;

import java.text.ParseException;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.store.DateInFileName;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTF8String;

public class CMPRequestFileNameHelper {
	public static final String requestLockFileName = ".lock.cmp";
	public static final String requestLockWriterLockFileName = ".lock.cmp.lock";
	public static final String cmpRequestFileName = ".conv.cmp";
	public static final String actionFileSuffix = ".action.cmp";
	public static final String actionDataFileSuffix = ".adata.cmp";
	public static final String requestFileSuffix = ".req.cmp";
	public static final String responseFileSuffix = ".rep.cmp";
	public static final String pollRequestFileSuffix = ".pollReq.cmp";
	public static final String pollResponseFileSuffix = ".pollRep.cmp";
	public static final String resultFileSuffix = ".res.cmp";

	private static final String FILEPARTSEPARATOR="_";

	public static String makeFileName(CMPRequest cmpRequest){
		return makeFileName(cmpRequest.getTransactionID(), cmpRequest.getCreated(), 
				cmpRequest.getMessageType(),cmpRequest.getWorkflowId());
	}
	public static String makeFileName(ASN1OctetString transactionID, 
			DERGeneralizedTime created, ASN1Integer requestType, DERUTF8String workflowId){
		String hexEncodedTxId = KeyIdUtils.hexEncode(transactionID);
		Date createUtilDate;
		try {
			createUtilDate = created.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		return new StringBuilder(hexEncodedTxId)
			.append(FILEPARTSEPARATOR)
			.append(DateInFileName.toFileName(createUtilDate))
			.append(FILEPARTSEPARATOR)
			.append(requestType.getValue().intValue())
			.append(FILEPARTSEPARATOR)
			.append(workflowId.getString().hashCode())
			.toString();
	}

	public static String getTransactionID(String[] nameComponents){
		return nameComponents[0];
	}

	public static Date getCreated(String[] nameComponents){
		String substring = nameComponents[1];
		return DateInFileName.fromFileName(substring);
	}

	public static String getRequestType(String[] nameComponents){
		return nameComponents[2];
	}

	public static String getWorkflowId(String[] nameComponents){
		return nameComponents[3];
	}

	public static String[] getNameComponents(String fileName){
		return fileName.split(FILEPARTSEPARATOR);
	}
	
	public static String getTransactionID(String fileName){
		return getTransactionID(getNameComponents(fileName));
	}

	public static Date getCreated(String fileName){
		return getCreated(getNameComponents(fileName));
	}
		
	public static String find(String[] children,  ASN1OctetString transactionID){
		if(children==null) return null;
		String txid = readTransactionID(transactionID);
		for (String fileName : children) {
			if(StringUtils.startsWithIgnoreCase(fileName, txid)) return fileName;
		}
		return null;
	}
	private static String readTransactionID(ASN1OctetString transactionID){
		return KeyIdUtils.hexEncode(transactionID) + FILEPARTSEPARATOR;
	}
	public static String findByMessageTypeAndWorkflowId(String[] children, int messageType, String workflowId){
		if(children==null) return null;
		String messageTypePart = "" + messageType;
		String workflowIdPart = "" + workflowId.hashCode();
		for (String fileName : children) {
			String[] nameComponents = getNameComponents(fileName);
			if(messageTypePart.equals(getRequestType(nameComponents)) && workflowIdPart.equals(getWorkflowId(nameComponents)))
				return fileName;
		}
		return null;
	}
}
