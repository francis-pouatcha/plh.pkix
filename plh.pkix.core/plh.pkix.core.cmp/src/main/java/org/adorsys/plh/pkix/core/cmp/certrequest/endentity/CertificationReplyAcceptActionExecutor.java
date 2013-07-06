package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
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
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.EncryptedValueParser;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;

/**
 * Processes a certification reply.
 * 
 * According to the CMP Specification, each certification reply might group responses of
 * one or more certification requests. But this framework assumes each certification request 
 * will be replied into a proper CMP message. This limits the extent of the CMP specification
 * for the sake of simplicity.
 * 
 * We instead use the List of Responses to map the transmission of the certificate chain 
 * associated with the issued certificate. The first response will carry the issued certificate.
 * The next one the ca certificate used to signed that certificate and the last one carrying a
 * root certificate.
 * 
 * From the actionContext, following information are required:
 * <ul>
 * 		<li>PKIMessageActionData. This carries the message being processed. 
 * 				Default entry of {@link PKIMessageActionData}</li>
 * 		<li>PrivateKeyEntry. PrivateKey entry associated with the certificate being 
 * 				issued. Keyed with the subjectKeyIdentifier of the associated
 * 				public key.</li>
 * </ul>
 * 
 * The result of the execute method is the certificate chain sent by the certification
 * authority.
 * 
 * @author francis
 *
 */
public class CertificationReplyAcceptActionExecutor {

	private static final String RESOURCE_NAME = CertRequestMessages.class
			.getName();

	private ActionContext actionContext;
	
	private final BuilderChecker checker = new BuilderChecker(CertificationReplyAcceptActionExecutor.class);
	public ProcessingResults<CertAndCertPath> execute() {

		checker.checkDirty().checkNull(actionContext);
		OutgoingRequests requests = actionContext.get(OutgoingRequests.class);
		CMPRequest cmpRequest = actionContext.get(CMPRequest.class);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		checker.checkDirty().checkNull(cmpRequest, contactManager);
		
		PKIMessage pkiMessage = requests.loadResponse(cmpRequest);
		CertReqMessages certReqMessages = CertReqMessages
				.getInstance(pkiMessage.getBody().getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		if(certReqMsgArray==null || certReqMsgArray.length<=0)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CertRequestMessages.CertRequestMessages_request_noCertrequestMessageInHolder);

		if(certReqMsgArray.length>1)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CertRequestMessages.CertRequestMessages_request_processOnlyFirstcertRequestMessage);
		
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
					CertRequestMessages.CertRequestMessages_response_certResponseEmpty);

		CMPCertificate[] caPubs = certRepMessage.getCaPubs();
		// put all certificate including caPubs in this array
		List<X509CertificateHolder> caCertificates = new ArrayList<X509CertificateHolder>();
		for (CMPCertificate cmpCertificate : caPubs) {
			caCertificates.add(new X509CertificateHolder(cmpCertificate.getX509v3PKCert()));
		}
		
		// iterate through the cert response and build the certification path.
		CertResponse certResponse = response[0];
		ASN1Integer crid = certResponse.getCertReqId();
			
		if(crid == null)// : "Missing cert request id, do not process";
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CertRequestMessages.CertRequestMessages_response_missingCertRequestId);
			
		if(!certReqId.equals(crid))
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CertRequestMessages.CertRequestMessages_response_wrongCertRequestId,
					new Object[]{KeyIdUtils.hexEncode(crid),
					KeyIdUtils.hexEncode(certReqId),
					KeyIdUtils.hexEncode(cmpRequest.getTransactionID())});
		
		SubjectKeyIdentifier publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifier(certTemplate.getPublicKey());
		PrivateKeyEntry subjectPrivateKeyEntry = contactManager.findEntryByPublicKeyIdentifier(PrivateKeyEntry.class, publicKeyIdentifier.getKeyIdentifier());
		if(subjectPrivateKeyEntry==null)
			throw PlhUncheckedException.toException(RESOURCE_NAME, 
					CertRequestMessages.CertRequestMessages_request_missingAssociatedPoP);

		X509CertificateHolder requestedCert = null;
		try {
			requestedCert = readCertificate(certResponse, subjectPrivateKeyEntry);
		} catch (CRMFException e) {
			throw PlhUncheckedException.toException(RESOURCE_NAME, 
					CertRequestMessages.CertRequestMessages_request_canNotDecryptCertificate);
		}
		
		List<X509CertificateHolder> allCertificates = new ArrayList<X509CertificateHolder>();
		allCertificates.add(requestedCert);
		allCertificates.addAll(caCertificates);
		PKIXParameters params = PKIXParametersFactory.makeParams(
				contactManager.getTrustAnchors(),
				contactManager.getCrl(),
				contactManager.findCertStores(allCertificates));
		
		ProcessingResults<CertAndCertPath> processingResults = new ProcessingResults<CertAndCertPath>();
			GeneralCertValidator generalCertValidator;

		generalCertValidator = new GeneralCertValidator()
				.withPKIXParameters(params)
				.withSenderSupliedCerts(V3CertificateUtils.createCertStore(allCertificates))
				.validate(new Date());
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
		processingResults.setReturnValue(new CertAndCertPath(requestedCert, certPathAndOrigin, validSignature));
		new CertificationReplyValidator()
			.withCertTemplate(certTemplate)
			.validate(processingResults);

		return processingResults;
	}

	public CertificationReplyAcceptActionExecutor withActionContext(ActionContext actionContext) {
		this.actionContext = actionContext;
		return this;
	}

	private X509CertificateHolder readCertificate(CertResponse certResponse, PrivateKeyEntry subjectPrivateKeyEntry) throws CRMFException{
		CertOrEncCert certOrEncCert = certResponse
				.getCertifiedKeyPair().getCertOrEncCert();
		EncryptedValue encryptedCert = certOrEncCert.getEncryptedCert();

		ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(
				subjectPrivateKeyEntry.getPrivateKey()).setProvider(ProviderUtils.bcProvider);
		EncryptedValueParser parser = new EncryptedValueParser(
				encryptedCert);
		return parser.readCertificateHolder(decGen);
	}
}
