package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.initrequest.InitRequestMessages;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.CertAndCertPath;
import org.adorsys.plh.pkix.core.utils.store.CertPathAndOrigin;
import org.adorsys.plh.pkix.core.utils.store.GeneralCertValidator;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Processes a initialization response.
 * 
 * According to the CMP Specification, each initialization reply might group responses of
 * one or more certification requests. But this framework assumes each certification request 
 * will be replied into a proper CMP message. This limits the extent of the CMP specification
 * for the sake of simplicity.
 * 
 * We instead use the List of Responses to map the transmission of the certificate chain 
 * associated with the issued certificate. The first response will carry the requested certificate.
 * The next one the ca certificate used to signed that certificate and the last one carrying a
 * root certificate.
 * 
 * From the actionContext, following information are required:
 * <ul>
 * 		<li>PKIMessageActionData. This carries the message being processed. 
 * 				Default entry of {@link PKIMessageActionData}</li>
 * </ul>
 * 
 * The result of the execute method is the certificate chain sent by the registration
 * authority.
 * 
 * @author francis
 *
 */
public class InitializationResponseAcceptActionExecutor {

	private static final String RESOURCE_NAME = InitRequestMessages.class.getName();

	private final BuilderChecker checker = new BuilderChecker(
			InitializationResponseAcceptActionExecutor.class);
	
	public List<ProcessingResults<CertAndCertPath>> execute(ActionContext actionContext) {

		checker.checkDirty().checkNull(actionContext);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		UserAccount userAccount = actionContext.get(UserAccount.class);
		checker.checkNull(cmpRequest, userAccount);
		
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		PKIMessage pkiMessage = requests.loadRequest(cmpRequest);
		CertReqMessages certReqMessages = CertReqMessages
				.getInstance(pkiMessage.getBody().getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		if(certReqMsgArray==null || certReqMsgArray.length<=0)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_request_noCertrequestMessageInHolder);

		if(certReqMsgArray.length>1)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_request_processOnlyFirstcertRequestMessage);
		
		CertReqMsg certReqMsg = certReqMsgArray[0];
		ASN1Integer certReqId=certReqMsg.getCertReq().getCertReqId();
		// the original template
		CertTemplate certTemplate = certReqMsg.getCertReq().getCertTemplate();
		
		PKIMessage responseMessage = requests.loadResponse(cmpRequest);
		CertRepMessage certRepMessage = CertRepMessage.getInstance(responseMessage.getBody().getContent());

		// check that sender is the addressed CA
		CertResponse[] response = certRepMessage.getResponse();
		if(response.length<=0)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					InitRequestMessages.InitRequestMessages_response_certResponseEmpty);

		CMPCertificate[] caPubs = certRepMessage.getCaPubs();
		// put all certificate including caPubs in this array
		List<X509CertificateHolder> caCertificates = new ArrayList<X509CertificateHolder>();
		for (CMPCertificate cmpCertificate : caPubs) {
			caCertificates.add(new X509CertificateHolder(cmpCertificate.getX509v3PKCert()));
		}
		
		// iterate through the cert response and build the certification path.
		List<X509CertificateHolder> requestedCerts = new ArrayList<X509CertificateHolder>();
		for (int i = 0; i < response.length; i++) {
			CertResponse certResponse = response[i];
			ASN1Integer crid = certResponse.getCertReqId();
			
			if(crid == null)// : "Missing cert request id, do not process";
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						InitRequestMessages.InitRequestMessages_response_missingCertRequestId);
			
			if(!certReqId.equals(crid))
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						InitRequestMessages.InitRequestMessages_response_wrongCertRequestId,
						new Object[]{KeyIdUtils.hexEncode(crid),
						KeyIdUtils.hexEncode(certReqId),
						KeyIdUtils.hexEncode(cmpRequest.getTransactionID())});
			
			CertOrEncCert certOrEncCert = certResponse
					.getCertifiedKeyPair().getCertOrEncCert();
			CMPCertificate cmpCertificate = certOrEncCert.getCertificate();
			requestedCerts.add(new X509CertificateHolder(cmpCertificate.getX509v3PKCert()));
		}

		List<X509CertificateHolder> allCertificates = new ArrayList<X509CertificateHolder>(requestedCerts);
		allCertificates.addAll(caCertificates);
		ContactManager contactManager = userAccount.getTrustedContactManager();
		PKIXParameters params = PKIXParametersFactory.makeParams(
				contactManager.getTrustAnchors(),
				contactManager.getCrl(),
				contactManager.findCertStores(allCertificates));
		
		List<ProcessingResults<CertAndCertPath>> certValidationResults = new ArrayList<ProcessingResults<CertAndCertPath>>(requestedCerts.size());
		for (X509CertificateHolder x509CertificateHolder : requestedCerts) {
			ProcessingResults<CertAndCertPath> processingResults = new ProcessingResults<CertAndCertPath>();
			GeneralCertValidator generalCertValidator;

			Date now = new Date();
			X509Certificate cert = V3CertificateUtils.getX509JavaCertificate(x509CertificateHolder);
			generalCertValidator = new GeneralCertValidator()
					.withPKIXParameters(params)
					.withSenderSupliedCerts(V3CertificateUtils.createCertStore(allCertificates))
					.withCert(cert)
					.validate(now);
			processingResults.addErrors(generalCertValidator.getErrors());
			processingResults.addNotifications(generalCertValidator.getNotifications());

			CertPathAndOrigin certPathAndOrigin = generalCertValidator.getCertPathAndOrigin();
			CertPath certPath = certPathAndOrigin.getCertPath();
			boolean validSignature = false;
			List<? extends Certificate> certificates = certPath.getCertificates();
			if(certificates.size()>1){
				Certificate targetCertificate = certificates.get(0);
				try {
					targetCertificate.verify(certificates.get(1).getPublicKey());
					validSignature=true;
				} catch (Exception e) {
					// noop
				}
			}
			processingResults.setReturnValue(new CertAndCertPath(x509CertificateHolder, certPathAndOrigin, validSignature));
			
			new InitializationReplyValidator()
				.withCertTemplate(certTemplate)
				.validate(processingResults);

			certValidationResults.add(processingResults);
		}

		return certValidationResults;
	}
}
