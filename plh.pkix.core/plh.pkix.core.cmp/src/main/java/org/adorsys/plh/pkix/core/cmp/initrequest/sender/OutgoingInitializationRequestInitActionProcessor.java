package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * An initialization request sends a request to another end entity to retrieve certificates. The unique
 * identifier of an initialization request must contain, the identifier of the certificate being requested and 
 * an identifier of the receiver of the request.
 * 
 * @author francis
 *
 */
public class OutgoingInitializationRequestInitActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		OutgoingRequests requestOut = context.get(OutgoingRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		ContactManager contactManager = context.get(ContactManager.class);
		checker.checkNull(contactManager,requestOut,actionHandler);
		
		CMPRequest cmpRequest = context.get(CMPRequest.class);// If the process was started by a user, this is non null
		
			
		if(cmpRequest==null){
			InitializationRequestFieldHolder f = context.get(InitializationRequestFieldHolder.class);	// user start a similar process
			checker.checkNull(f);
			String workflowId = f.getWorkflowId();
			cmpRequest = requestOut.loadRequest(PKIBody.TYPE_INIT_REQ, f.getWorkflowId());// we find a process instance with the same workflow id
			if(cmpRequest==null){// new process
				ASN1ProcessingResult processingResult = null;
				try {
					OutgoingInitializationRequestInitActionExecutor builder = new OutgoingInitializationRequestInitActionExecutor()
					.withWorkflowId(workflowId)
					.withCertAuthorityName(f.getCertAuthorityName())
					.withNotAfter(f.getNotAfter())
					.withNotBefore(f.getNotBefore())
					.withReceiverCertificate(f.getReceiverCertificate())
					.withReceiverEmail(f.getReceiverEmail())
					.withSubjectAltNames(f.getSubjectAltNames())
					.withSubjectDN(f.getSubjectDN())
					.withSubjectPublicKeyInfo(f.getSubjectPublicKeyInfo());
					if(f.isCaSet())builder = builder.withCa(f.isCa());
					if(f.isKeyUsageSet())builder=builder.withKeyUsage(f.getKeyUsage());
					
					PrivateKeyEntry privateKeyEntry = contactManager.getMainMessagePrivateKeyEntry();
					cmpRequest = builder.build(privateKeyEntry, context);

					ASN1Action nextAction = new ASN1Action(
							cmpRequest.getTransactionID(), 
							new DERGeneralizedTime(new Date()), 
							UUIDUtils.newUUIDasASN1OctetString(), 
							new DERIA5String(OutgoingInitializationRequestInitPostAction.class.getName()));
					
					requestOut.setResultAndNextAction(cmpRequest, processingResult, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, null);
				} catch(PlhUncheckedException e){
					cmpRequest = new CMPRequest(new ASN1Integer(PKIBody.TYPE_INIT_REQ), new DERUTF8String(workflowId));
					requestOut.newRequest(cmpRequest);
					processingResult=ErrorMessageHelper.getASN1ProcessingResult(e.getErrorMessage());
//				} catch (RuntimeException r){
//					cmpRequest = new CMPRequest(new ASN1Integer(PKIBody.TYPE_INIT_REQ), new DERUTF8String(workflowId));
//					requestOut.newRequest(cmpRequest);
//					ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(r, getClass());
//					processingResult=ErrorMessageHelper.getASN1ProcessingResult(errorMessage);
				}

			}
		}
		GenericOutgoingInitializationActionRegistry.executeAction(cmpRequest, context);// execute
	}
}
