package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * 
 * @author francis
 *
 */
public class CertificationRequestInitActionProcessor implements ActionProcessor {
	
	private final BuilderChecker checker = new BuilderChecker(CertificationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		OutgoingRequests requestOut = context.get(OutgoingRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		ContactManager contactManager = context.get(ContactManager.class);
		checker.checkNull(contactManager,requestOut,actionHandler);
		
		CMPRequest cmpRequest = context.get(CMPRequest.class);// If the process was started by a user, this is non null

		if(cmpRequest==null){
			CertificationRequestFieldHolder f = context.get(CertificationRequestFieldHolder.class);	// user start a similar process
			checker.checkNull(f);
			String workflowId = f.getWorkflowId();
			cmpRequest = requestOut.loadRequest(PKIBody.TYPE_CERT_REQ, f.getWorkflowId());// we find a process instance with the same workflow id
			if(cmpRequest==null){// new process
				
				CertificationRequestInitActionExecutor builder = new CertificationRequestInitActionExecutor()
				.withWorkflowId(workflowId)
				.withCertAuthorityName(f.getCertAuthorityName())
				.withNotAfter(f.getNotAfter())
				.withNotBefore(f.getNotBefore())
				.withReceiverCertificate(f.getReceiverCertificate())
				.withReceiverEmail(f.getReceiverEmail())
				.withSubjectAltNames(f.getSubjectAltNames())
				.withSubjectDN(f.getSubjectDN())
				.withSubjectOnlyInAlternativeName(f.isSubjectOnlyInAlternativeName())
				.withSubjectPublicKeyInfo(f.getSubjectPublicKeyInfo());

		
				if(f.isCaSet())builder = builder.withCa(f.isCa());
				if(f.isKeyUsageSet())builder=builder.withKeyUsage(f.getKeyUsage());
		
				PrivateKeyEntry privateKeyEntry = contactManager.getMainMessagePrivateKeyEntry();
				PKIMessage pkiMessage = builder.build(privateKeyEntry, f.getPrivateKeyEntryToCertify());
				cmpRequest = new CMPRequest(pkiMessage.getHeader().getTransactionID(), 
						new DERGeneralizedTime(new Date()), new ASN1Integer(PKIBody.TYPE_CERT_REQ), new DERUTF8String(workflowId));
				requestOut.newRequest(cmpRequest);
				ASN1Action nextAction = new ASN1Action(
						cmpRequest.getTransactionID(), 
						new DERGeneralizedTime(new Date()), 
						UUIDUtils.newUUIDasASN1OctetString(), 
						new DERIA5String(CertificationRequestInitPostAction.class.getName()));
				
				requestOut.setRequest(cmpRequest, pkiMessage);
				requestOut.setResultAndNextAction(cmpRequest, null, 
						new DERIA5String(ProcessingStatus.SUCCESS), nextAction, null);
			}
		}
		GenericCertRequestActionRegistery.executeAction(cmpRequest, context);// execute
	}
}
