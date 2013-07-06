package org.adorsys.plh.pkix.core.cmp.pollrequest;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;

public class PollRequestBuilder {

	private final BuilderChecker checker = new BuilderChecker(PollReplyValidationPostAction.class);
    public void build(ActionContext actionContext) {
//    	checker.checkDirty().checkNull(actionContext);
//    	PendingRequestData pendingRequestSData = actionContext.get(PendingRequestData.class);
//    	KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
//    	checker.checkNull(pendingRequestSData);
//        
//        PKIMessage pollRepPKIMessage = pendingRequestSData.getPendingRequest().getPollRepMessage();
//        GeneralPKIMessage pollRepGeneralPKIMessage = new GeneralPKIMessage(pollRepPKIMessage);
//        PKIHeader pollRepPkiHeader = pollRepGeneralPKIMessage.getHeader();
//        PollRepContent pollRepContent = PollRepContent.getInstance(pollRepGeneralPKIMessage.getBody().getContent());
//		
//		DERSequence derSequence = new DERSequence(new DERSequence(pollRepContent.getCertReqId()));
//		PollReqContent pollReqContent = PollReqContent.getInstance(derSequence);
//	
//		ASN1OctetString recipKID = pollRepPKIMessage.getHeader().getRecipKID();
//		PrivateKeyEntry privateKeyEntry = null;
//		if(recipKID!=null){
//			privateKeyEntry = keyStoreWraper.findPrivateKeyEntryBySubjectKeyIdentifier(recipKID.getOctets());
//		}
//		
//		if(privateKeyEntry==null){
//			privateKeyEntry = keyStoreWraper.findAnyMessagePrivateKeyEntry();
//		}
//		
//		Certificate certificate = privateKeyEntry.getCertificate();
//		X509CertificateHolder subjectCert;
//		try {
//			subjectCert = new X509CertificateHolder(certificate.getEncoded());
//		} catch (CertificateEncodingException e) {
//			throw new IllegalStateException(e);
//		} catch (IOException e) {
//			throw new IllegalStateException(e);
//		}
//        GeneralName subject = new GeneralName(subjectCert.getSubject());
//		ContentSigner subjectSigner;
//		try {
//			subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
//			.setProvider(ProviderUtils.bcProvider).build(privateKeyEntry.getPrivateKey());
//		} catch (OperatorCreationException e) {
//			throw new IllegalStateException(e);
//		}
//
//		byte[] subjectKeyId = KeyIdUtils.readSubjectKeyIdentifierAsByteString(subjectCert);
//
//		ProtectedPKIMessage mainMessage;
//		try {
//			mainMessage = new ProtectedPKIMessageBuilder(subject, pollRepPkiHeader.getSender())
//			                                          .setBody(new PKIBody(PKIBody.TYPE_POLL_REQ, pollReqContent))
//			                                          .addCMPCertificate(subjectCert)
//			                                          .setMessageTime(new Date())
//			                                          .setSenderKID(subjectKeyId)
//			                                          .setSenderNonce(UUIDUtils.newUUIDAsBytes())
//			                                          .setRecipNonce(pollRepPkiHeader.getSenderNonce().getOctets())
//			                                          .setTransactionID(pollRepPkiHeader.getTransactionID().getOctets())
//			                                          .build(subjectSigner);
//		} catch (CMPException e) {
//			throw new IllegalStateException(e);
//		}
//		
//		PKIMessage pollReqPKIMessage = mainMessage.toASN1Structure();
//		setPollReqMessage(pollReqPKIMessage, pendingRequestSData, actionContext);
	}
    
//	private void setPollReqMessage(PKIMessage pollReqPKIMessage, PendingRequestData pendingRequestData, ActionContext actionContext) {
//		PendingRequest pendingPollRequest = pendingRequestData.getPendingRequest();
//		pendingPollRequest = new PendingRequest(
//				pendingPollRequest.getCertReqId(), 
//				pendingPollRequest.getPkiMessage(), 
//				pendingPollRequest.getNextPoll(), 
//				pendingPollRequest.getPollRepMessage(), 
//				pollReqPKIMessage,
//				pendingPollRequest.getDisposed());
//		PendingRequestData prd = new PendingRequestData(pendingPollRequest);
//		actionContext.put(PendingRequestData.class, null, prd);
//	}
    
}
