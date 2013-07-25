package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChain;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificationResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificationResults;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

public class CertReqResponseActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(
			CertReqResponseActionProcessor.class);

	@Override
	public void process(ActionContext context) {

		checker.checkNull(context);

		ContactManager contactManager = context.get(ContactManager.class);

		IncomingRequests requests = context.get(IncomingRequests.class);
		CMPRequest cmpRequest = context.get(CMPRequest.class);
		checker.checkNull(cmpRequest, requests);

		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			byte[] actionData = requests.loadActionData(cmpRequest);
			if (actionData == null)
				return;
			ASN1CertificationResults asn1CertificationResults = ASN1CertificationResults
					.getInstance(actionData);

			PKIMessage pkiMessage = requests.loadRequest(cmpRequest);
			PKIBody pkiBody = pkiMessage.getBody();

			CertReqMessages certReqMessages = CertReqMessages
					.getInstance(pkiBody.getContent());
			CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
			ASN1CertificationResult[] certificationResults = asn1CertificationResults
					.toResultArray();
			List<CertResponse> certResponses = new ArrayList<CertResponse>();
			// Use set to filter duplicates.
			// ToDo: check that the equals method of
			// org.bouncycastle.asn1.x509.Certificate works.
			Set<org.bouncycastle.asn1.x509.Certificate> caPublicKeySet = new HashSet<org.bouncycastle.asn1.x509.Certificate>();
			for (int i = 0; i < certReqMsgArray.length; i++) {
				CertReqMsg certReqMsg = certReqMsgArray[i];
				CertRequest certReq = certReqMsg.getCertReq();
				ASN1CertificationResult asn1CertificationResult = null;
				for (ASN1CertificationResult c : certificationResults) {
					if (certReq.getCertReqId().equals(c.getCertReqId())) {
						asn1CertificationResult = c;
						break;
					}
				}
				if (asn1CertificationResult == null)
					continue;

				ASN1CertificateChain certificateChain = asn1CertificationResult
						.getCertificateChain();
				org.bouncycastle.asn1.x509.Certificate[] certArray = certificateChain
						.toCertArray();
				CertResponse certResponse = createCertResponse(certArray[0],
						asn1CertificationResult);
				certResponses.add(certResponse);

				if (certArray.length > 0) {// add all except the certificate
					for (int j = 1; j < certArray.length; j++) {
						caPublicKeySet.add(certArray[j]);
					}
				}
			}

			List<CMPCertificate> caPublicKeyList = new ArrayList<CMPCertificate>();
			for (org.bouncycastle.asn1.x509.Certificate certificate : caPublicKeySet) {
				caPublicKeyList.add(new CMPCertificate(certificate));
			}
			CMPCertificate[] caPubs = caPublicKeyList
					.toArray(new CMPCertificate[caPublicKeyList.size()]);

			// create the reply message
			CertResponse[] response = certResponses
					.toArray(new CertResponse[certResponses.size()]);
			CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);

			PKIHeader header = pkiMessage.getHeader();
			GeneralName certificateRecipient = header.getSender();
			ASN1OctetString myPublicKeyIdentifier = header.getRecipKID();
			PrivateKeyEntry privateKeyEntry = null;
			if (myPublicKeyIdentifier != null)
				privateKeyEntry = contactManager
						.findEntryByPublicKeyIdentifier(PrivateKeyEntry.class,
								myPublicKeyIdentifier.getOctets());

			if (privateKeyEntry == null && header.getRecipient() != null) {
				GeneralName me = header.getRecipient();
				String myEmail = X500NameHelper.readEmail(me);
				if (myEmail != null)
					privateKeyEntry = contactManager.findMessageEntryByEmail(
							PrivateKeyEntry.class, myEmail);
			}

			if (privateKeyEntry == null)
				privateKeyEntry = contactManager
						.getMainMessagePrivateKeyEntry();

			Certificate myCertificate = privateKeyEntry.getCertificate();
			X509CertificateHolder myCertificateHolder = V3CertificateUtils
					.getX509CertificateHolder(myCertificate);
			X500Name senderDN = X500NameHelper
					.readSubjectDN(myCertificateHolder);
			ProtectedPKIMessage mainMessage;
			byte[] senderKeyID = KeyIdUtils
					.createPublicKeyIdentifierAsByteString(myCertificateHolder);
			ProtectedPKIMessageBuilder protectedPKIMessageBuilder = new ProtectedPKIMessageBuilder(
					new GeneralName(senderDN), certificateRecipient)
					.setBody(new PKIBody(PKIBody.TYPE_CERT_REP, certRepMessage))
					.addCMPCertificate(myCertificateHolder)
					.setMessageTime(new Date()).setSenderKID(senderKeyID)
					.setRecipKID(header.getSenderKID().getOctets())
					.setRecipNonce(header.getSenderNonce().getOctets())
					.setSenderNonce(UUIDUtils.newUUIDAsBytes())
					.setTransactionID(header.getTransactionID().getOctets());

			ContentSigner senderSigner = V3CertificateUtils.getContentSigner(
					privateKeyEntry.getPrivateKey(), "MD5WithRSAEncryption");

			try {
				mainMessage = protectedPKIMessageBuilder.build(senderSigner);
			} catch (CMPException e) {
				throw PlhUncheckedException.toException(e, getClass());
			}

			PKIMessage responseMessage = mainMessage.toASN1Structure();
			requests.setResponse(cmpRequest, responseMessage);

			ASN1Action nextAction = new ASN1Action(
					cmpRequest.getTransactionID(), new DERGeneralizedTime(
							new Date()), UUIDUtils.newUUIDasASN1OctetString(),
					new DERIA5String(CertReqResponsePostAction.class.getName()));

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(
					ProcessingStatus.SUCCESS), nextAction, null);

			executeAction = true;
		} catch (PlhUncheckedException e) {
			ErrorMessageHelper.processError(cmpRequest, requests,
					e.getErrorMessage());
//		} catch (RuntimeException r) {
//			ErrorBundle errorMessage = PlhUncheckedException.toErrorMessage(r,
//					getClass().getName() + "#process");
//			ErrorMessageHelper.processError(cmpRequest, requests, errorMessage);
		} finally {
			requests.unlock(cmpRequest);
		}
		if (executeAction)
			GenericCertResponseActionRegistry
					.executeAction(cmpRequest, context);// execute

	}

	/**
	 * For PoP we will encrypt the requested certificate with the corresponding public. So requestor 
	 * can decrypt the certificate for proving ownership of the private key.
	 * @param bcCertificate
	 * @param asn1CertificationResult
	 * @return
	 */
	private CertResponse createCertResponse(
			org.bouncycastle.asn1.x509.Certificate bcCertificate,
			ASN1CertificationResult asn1CertificationResult) 
	{
		X509CertificateHolder issuedCertificate = V3CertificateUtils.getX509CertificateHolder(bcCertificate);
		PublicKey subjectPublicKey = V3CertificateUtils.extractPublicKey(issuedCertificate);

		// Encrypt certificate
		JceAsymmetricKeyWrapper jceAsymmetricKeyWrapper = new JceAsymmetricKeyWrapper(subjectPublicKey);
		OutputEncryptor encryptor;
		try {
			encryptor = new JceCRMFEncryptorBuilder(
					PKCSObjectIdentifiers.des_EDE3_CBC).setProvider(
					ProviderUtils.bcProvider).build();
		} catch (CRMFException e) {
			throw new IllegalStateException(e);
		}
		JcaEncryptedValueBuilder jcaEncryptedValueBuilder = new JcaEncryptedValueBuilder(jceAsymmetricKeyWrapper, encryptor);
		EncryptedValue encryptedCert;
		try {
			encryptedCert = jcaEncryptedValueBuilder.build(issuedCertificate);
		} catch (CRMFException e) {
			throw new IllegalStateException(e);
		}
		
		// Package certificate
		CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(new CertOrEncCert(encryptedCert));
		PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
		ASN1OctetString rspInfo = null;
		return new CertResponse(asn1CertificationResult.getCertReqId(), status, certifiedKeyPair, rspInfo);
	}

}
