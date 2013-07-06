package org.adorsys.plh.pkix.core.cmp.registration;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Initializes a registration request. Stores the request only if the initialization works.
 * 
 * @author francis
 *
 */
public class RegistrationRequestInitActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(RegistrationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		OutgoingRequests requestOut = context.get(OutgoingRequests.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		checker.checkNull(requestOut,actionHandler);

		CMPRequest cmpRequest = context.get(CMPRequest.class);// If the process was started by a user, this is non null
		if(cmpRequest==null){
			// The private key entry to be registered.
			PrivateKeyEntry keyToRegister = context.get(PrivateKeyEntry.class);
			checker.checkNull(keyToRegister);
			
			KeyStoreAlias keyStoreAlias = getKeyStoreAlias(keyToRegister);
			// check if existing request, and return
			cmpRequest = requestOut.loadRequest(PKIBody.TYPE_INIT_REQ, keyStoreAlias.getAlias());
			if(cmpRequest==null){// continue with the existing process
				// create and store the request.
				cmpRequest = new RegistrationRequestInitActionExecutor().build(keyToRegister,context);	// new process		
				if(cmpRequest==null){
					cmpRequest=new CMPRequest(new ASN1Integer(PKIBody.TYPE_INIT_REQ), new DERUTF8String(keyStoreAlias.getAlias()));
					requestOut.newRequest(cmpRequest);
				}
				
				ASN1Action nextAction = new ASN1Action(
						cmpRequest.getTransactionID(), 
						new DERGeneralizedTime(new Date()), 
						UUIDUtils.newUUIDasASN1OctetString(), 
						new DERIA5String(RegistrationRequestInitPostAction.class.getName()));
				requestOut.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS),
						nextAction, null);
			}
		}
		GenericRegistrationActionRegistry.executeAction(cmpRequest, context);
	}

	private KeyStoreAlias getKeyStoreAlias(PrivateKeyEntry privateKeyEntry){
		X509CertificateHolder subjectCertificateHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
		return new KeyStoreAlias(subjectCertificateHolder, PrivateKeyEntry.class);		
	}
}
