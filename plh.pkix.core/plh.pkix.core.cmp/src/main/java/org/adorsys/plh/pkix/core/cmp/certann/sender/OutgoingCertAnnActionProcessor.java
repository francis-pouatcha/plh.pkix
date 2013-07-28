package org.adorsys.plh.pkix.core.cmp.certann.sender;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainImportResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertChainImprortResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertImportResult;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

public class OutgoingCertAnnActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingCertAnnActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {
		checker.checkNull(actionContext);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		UserAccount userAccount = actionContext.get(UserAccount.class);
		checker.checkNull(cmpRequest, requests, userAccount);

		requests.lock(cmpRequest);
		boolean execueAction = false;
		ASN1CertChainImportResult[] certChainImprortResultArray = null;
		X509CertificateHolder receiverCertificateHolder = null;
		PrivateKeyEntry privateKeyEntry = null;
		try {
			byte[] actionData = requests.loadActionData(cmpRequest);
			if(actionData==null) return;
			ASN1CertChainImprortResults certChainImprortResults = ASN1CertChainImprortResults.getInstance(actionData);
			certChainImprortResultArray = certChainImprortResults.toArray();
			privateKeyEntry = userAccount.getAnyMessagePrivateKeyEntry();
			
			// we assume receiver is the issuing instance
			PKIMessage response = requests.loadResponse(cmpRequest);
			if(response==null) return;
			ProtectedPKIMessage protectedResponseMessage = new ProtectedPKIMessage(new GeneralPKIMessage(response));
			X509CertificateHolder[] senderCertificates = protectedResponseMessage.getCertificates();
			if(senderCertificates.length<=0) return;
			receiverCertificateHolder = senderCertificates[0];
			
			execueAction = true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
//		} catch(RuntimeException e){
//			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(e, getClass().getName()+"#process");
//			ErrorMessageHelper.processError(cmpRequest, requests, errorMessage);
		} finally {
			requests.unlock(cmpRequest);
		}
		
		if(execueAction && receiverCertificateHolder!=null && privateKeyEntry!=null && certChainImprortResultArray!=null){
			for (ASN1CertChainImportResult asn1CertChainImportResult : certChainImprortResultArray) {
				ASN1CertImportResult[] asn1CertImportResults = asn1CertChainImportResult.toArray();
				if(asn1CertImportResults.length<=0) continue;
				ASN1CertImportResult certImportResult = asn1CertImportResults[0];
				Certificate certificateAnnounced = certImportResult.getCertificate();
				String workflowId = CertAnnWorkflowId.getWorkflowId(certificateAnnounced.getSerialNumber().getValue(), 
						receiverCertificateHolder.getSerialNumber());
				
				CMPCertificate cmpCertificate = new CMPCertificate(certificateAnnounced);
				PKIMessage pkiMessage = new OutgoingCertAnnActionExecutor()
					.withCmpCertificate(cmpCertificate)
					.withReceiverCertificate(receiverCertificateHolder)
					.withWorkflowId(workflowId)
					.build(privateKeyEntry);
				
				CMPRequest subCMPRequest = new CMPRequest(pkiMessage.getHeader().getTransactionID(), 
						new DERGeneralizedTime(new Date()), new ASN1Integer(PKIBody.TYPE_CERT_ANN), new DERUTF8String(workflowId));
				requests.newRequest(subCMPRequest);
				requests.setRequest(subCMPRequest, pkiMessage);
	
				ASN1Action nextAction = new ASN1Action(
						subCMPRequest.getTransactionID(), 
						new DERGeneralizedTime(new Date()), 
						UUIDUtils.newUUIDasASN1OctetString(), 
						new DERIA5String(OutgoingCertAnnPostAction.class.getName()));
				
				requests.setResultAndNextAction(subCMPRequest, null, 
						new DERIA5String(ProcessingStatus.SUCCESS), nextAction, null);
				
				GenericOutgoingCertAnnActionRegistery.executeAction(subCMPRequest, actionContext);// execute
			}
		}
	}
}
