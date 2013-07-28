package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.ErrorMessageHelper;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.ProcessingStatus;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias.PurposeEnum;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
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
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;

public class OutgoingInitializationResponseActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationResponseActionProcessor.class);
	@Override
	public void process(ActionContext context) {

		checker.checkNull(context);
		UserAccount userAccount = context.get(UserAccount.class);
		
		IncomingRequests requests = context.get(IncomingRequests.class);
		CMPRequest cmpRequest = context.get(CMPRequest.class);
		checker.checkNull(cmpRequest,requests, userAccount);
		boolean executeAction = false;
		requests.lock(cmpRequest);
		try {
			PKIMessage pkiMessage = requests.loadRequest(cmpRequest);
			PKIBody pkiBody = pkiMessage.getBody();
			ProtectedPKIMessage protectedPKIMessage=new ProtectedPKIMessage(new GeneralPKIMessage(pkiMessage));
			
			CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody.getContent());
			CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
			List<CertResponse> certResponses = new ArrayList<CertResponse>();
			List<CMPCertificate> caPublickeys = new ArrayList<CMPCertificate>();
			
			for (CertReqMsg certReqMsg : certReqMsgArray) {
				CertRequest certReq = certReqMsg.getCertReq();
				CertTemplate certTemplate = certReq.getCertTemplate();
	
				List<TrustedCertificateEntry> certEntries = null;
				List<PrivateKeyEntry> keyEntries = null;
				
				PurposeEnum purpose = null;
				if(V3CertificateUtils.isCaKey(certTemplate)){
					purpose = PurposeEnum.CA;
				} else if (V3CertificateUtils.isSmimeKey(certTemplate)){
					purpose=PurposeEnum.ME;
				}
				// we start searching with the public key
				SubjectKeyIdentifier subjectKeyIdentifier = KeyIdUtils.createPublicKeyIdentifier(certTemplate.getPublicKey());
				if(subjectKeyIdentifier==null)
					subjectKeyIdentifier = KeyIdUtils.readSubjectKeyIdentifier(certTemplate);

				if(subjectKeyIdentifier!=null){
					String subjectKeyIdHex = KeyIdUtils.subjectKeyIdentifierToString(subjectKeyIdentifier);
					KeyStoreAlias privateKeyStoreAlias = new KeyStoreAlias(subjectKeyIdHex, null, null, purpose, PrivateKeyEntry.class);
					keyEntries = userAccount.getPrivateContactManager().findEntriesByAlias(PrivateKeyEntry.class, privateKeyStoreAlias);
					KeyStoreAlias trustedCertStoreAlias = new KeyStoreAlias(subjectKeyIdHex, null, null, purpose, TrustedCertificateEntry.class);
					certEntries = userAccount.getTrustedContactManager().findEntriesByAlias(TrustedCertificateEntry.class, trustedCertStoreAlias);
				}

				// lets try with the subject email if the DN does not produce
				// any result.
				if((certEntries==null || certEntries.isEmpty()) && (keyEntries==null || keyEntries.isEmpty())){
					List<String> subjectEmails = X500NameHelper.readSubjectEmails(certTemplate);
					if(subjectEmails!=null && !subjectEmails.isEmpty()){
						String[] emails = subjectEmails.toArray(new String[subjectEmails.size()]);
						certEntries = userAccount.getTrustedContactManager().findEntriesByEmail(TrustedCertificateEntry.class, emails);
						keyEntries = userAccount.getPrivateContactManager().findEntriesByEmail(PrivateKeyEntry.class, emails);
					}
				}
				
				if((certEntries==null || certEntries.isEmpty()) && (keyEntries==null || keyEntries.isEmpty()))
					continue;

				certEntries = filterCertContacts(certEntries, purpose);
				keyEntries = filterPrivateKeyContacts(keyEntries, purpose);
				
				certEntries = filterContacts0(certEntries, certTemplate.getValidity());
				keyEntries = filterContacts(keyEntries, certTemplate.getValidity());
	
				certEntries = filterContacts0(certEntries, KeyIdUtils.readAuthorityKeyIdentifier(certTemplate));
				keyEntries = filterContacts(keyEntries, KeyIdUtils.readAuthorityKeyIdentifier(certTemplate));
	
				certEntries = filterContacts0(certEntries, certTemplate.getIssuerUID());
				keyEntries = filterContacts(keyEntries, certTemplate.getIssuerUID());
				
				certEntries = filterContactsByIssuer0(certEntries, certTemplate.getIssuer());
				keyEntries = filterContactsByIssuer(keyEntries, certTemplate.getIssuer());
	
				if((certEntries==null || certEntries.isEmpty()) && (keyEntries==null || keyEntries.isEmpty()))
					continue;
				
				if(keyEntries!=null)
				for (PrivateKeyEntry privateKeyEntry : keyEntries) {					
					certResponses.add(createCertResponse(privateKeyEntry.getCertificate(), certReq.getCertReqId()));
					Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
					if(certificateChain.length>1)
						for (int i = 1; i < certificateChain.length; i++) {
							Certificate certificate = certificateChain[i];					
							org.bouncycastle.asn1.x509.Certificate bcCertificate = V3CertificateUtils.getX509BCCertificate(certificate);
							CMPCertificate cmpCertificate = new CMPCertificate(bcCertificate);
							if(!caPublickeys.contains(cmpCertificate))
								caPublickeys.add(cmpCertificate);
						}
				}
				
				if(certEntries!=null)
				for (TrustedCertificateEntry trustedCertificateEntry : certEntries) {
					certResponses.add(createCertResponse(trustedCertificateEntry.getTrustedCertificate(), certReq.getCertReqId()));
				}
			}
			
			CMPCertificate[] caPubs = null;
			if(caPublickeys!=null && !caPublickeys.isEmpty())
				caPubs = caPublickeys.toArray(new CMPCertificate[caPublickeys.size()]);

			CertResponse[] response = null;
			if(certResponses!=null && !certResponses.isEmpty())
				response = certResponses.toArray(new CertResponse[certResponses.size()]);
			
			CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);
			
			PrivateKeyEntry privateKeyEntry = null;
			
			PKIHeader header = protectedPKIMessage.getHeader();
			ASN1OctetString myPublicKeyIdentifier = header.getRecipKID();
			if(myPublicKeyIdentifier!=null){
				String publicKeyIdHex = KeyIdUtils.hexEncode(myPublicKeyIdentifier);
				KeyStoreAlias keyStoreAlias = new KeyStoreAlias(publicKeyIdHex, null, null, PurposeEnum.ME, PrivateKeyEntry.class);
				privateKeyEntry = userAccount.getPrivateContactManager().findEntryByAlias(PrivateKeyEntry.class, keyStoreAlias);
			}

			if(privateKeyEntry==null)
				privateKeyEntry = userAccount.getAnyMessagePrivateKeyEntry();
			
			
			GeneralName certificateRecipient = header.getSender();
			Certificate myCertificate = privateKeyEntry.getCertificate();
			X509CertificateHolder myCertificateHolder = V3CertificateUtils.getX509CertificateHolder(myCertificate);
			X500Name subjectDN = X500NameHelper.readSubjectDN(myCertificateHolder);
			ProtectedPKIMessage mainMessage;
			byte[] senderKeyID = KeyIdUtils.createPublicKeyIdentifierAsByteString(myCertificateHolder);
			ProtectedPKIMessageBuilder protectedPKIMessageBuilder = 
					new ProtectedPKIMessageBuilder(new GeneralName(subjectDN), certificateRecipient)
					.setBody(new PKIBody(PKIBody.TYPE_INIT_REP, certRepMessage))
					.addCMPCertificate(myCertificateHolder)
					.setMessageTime(new Date())
					.setSenderKID(senderKeyID)
					.setRecipKID(header.getSenderKID().getOctets())
					.setRecipNonce(header.getSenderNonce().getOctets())
					.setSenderNonce(UUIDUtils.newUUIDAsBytes())
					.setTransactionID(header.getTransactionID().getOctets());
			
			ContentSigner senderSigner = V3CertificateUtils.getContentSigner(privateKeyEntry.getPrivateKey(), "MD5WithRSAEncryption");
	
			try {
				mainMessage = protectedPKIMessageBuilder.build(senderSigner);
			} catch (CMPException e) {
				throw PlhUncheckedException.toException(e, getClass());
			}

			PKIMessage responseMessage = mainMessage.toASN1Structure();
			requests.setResponse(cmpRequest, responseMessage);
			
			ASN1Action nextAction = new ASN1Action(cmpRequest.getTransactionID(), 
				new DERGeneralizedTime(new Date()), 
				UUIDUtils.newUUIDasASN1OctetString(), 
				new DERIA5String(OutgoingInitializationResponsePostAction.class.getName()));

			requests.setResultAndNextAction(cmpRequest, null, new DERIA5String(ProcessingStatus.SUCCESS), nextAction, null);
			
			executeAction = true;
		} catch(PlhUncheckedException e){
			ErrorMessageHelper.processError(cmpRequest, requests, e.getErrorMessage());
		} finally {
			requests.unlock(cmpRequest);
		} 

		if(executeAction)
			GenericIncomingInitializationActionRegistry.executeAction(cmpRequest, context);// execute
	}

	private CertResponse createCertResponse(Certificate certificate, ASN1Integer certReqId){
		org.bouncycastle.asn1.x509.Certificate bcCertificate = V3CertificateUtils.getX509BCCertificate(certificate);
		CertOrEncCert certOrEncCert = new CertOrEncCert(new CMPCertificate(bcCertificate));
		CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert);
		PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
		ASN1OctetString rspInfo = null;
		return new CertResponse(certReqId, status, certifiedKeyPair, rspInfo);
	}
	
	private List<PrivateKeyEntry> filterContacts(List<PrivateKeyEntry> foundCertificates,OptionalValidity optionalValidity) {
		if(optionalValidity==null) return foundCertificates;
		List<PrivateKeyEntry> result =new ArrayList<PrivateKeyEntry>();
		OptionalValidityHolder validityHolder = new OptionalValidityHolder(optionalValidity);
		for (PrivateKeyEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getCertificate());
			if(V3CertificateUtils.isValid(certificateHolder, validityHolder.getNotBeforeAsDate(), validityHolder.getNotAfterAsDate()))
				result.add(entry);
		}
		return result;
	}
	private List<TrustedCertificateEntry> filterContacts0(
			List<TrustedCertificateEntry> foundCertificates,
			OptionalValidity optionalValidity) {
		if(optionalValidity==null) return foundCertificates;
		List<TrustedCertificateEntry> result =new ArrayList<TrustedCertificateEntry>();
		OptionalValidityHolder validityHolder = new OptionalValidityHolder(optionalValidity);
		for (TrustedCertificateEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getTrustedCertificate());
			if(V3CertificateUtils.isValid(certificateHolder, validityHolder.getNotBeforeAsDate(), validityHolder.getNotAfterAsDate()))
				result.add(entry);
		}
		return result;
	}

	private List<PrivateKeyEntry> filterContactsByIssuer(
			List<PrivateKeyEntry> foundCertificates, X500Name issuer) {
		if(issuer==null) return foundCertificates;

		List<PrivateKeyEntry> result = new ArrayList<PrivateKeyEntry>();
		for (PrivateKeyEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getCertificate());
			if(issuer.equals(certificateHolder.getIssuer()))result.add(entry);
		}
		return result;
	}
	private List<TrustedCertificateEntry> filterContactsByIssuer0(
			List<TrustedCertificateEntry> foundCertificates, X500Name issuer) {
		if(issuer==null) return foundCertificates;

		List<TrustedCertificateEntry> result = new ArrayList<TrustedCertificateEntry>();
		for (TrustedCertificateEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getTrustedCertificate());
			if(issuer.equals(certificateHolder.getIssuer()))result.add(entry);
		}
		return result;
	}

	private List<PrivateKeyEntry> filterContacts(
			List<PrivateKeyEntry> foundCertificates,
			DERBitString issuerUID) {
		if (issuerUID==null) return foundCertificates;
		byte[] issuerUIDBytes = issuerUID.getBytes();
		List<PrivateKeyEntry> result = new ArrayList<PrivateKeyEntry>();
		for (PrivateKeyEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getCertificate());
			byte[] createdPublicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(certificateHolder);
			if(Arrays.equals(createdPublicKeyIdentifier, issuerUIDBytes))
				result.add(entry);
		}
		return result;
	}
	private List<TrustedCertificateEntry> filterContacts0(
			List<TrustedCertificateEntry> foundCertificates,
			DERBitString issuerUID) {
		if (issuerUID==null) return foundCertificates;
		byte[] issuerUIDBytes = issuerUID.getBytes();
		List<TrustedCertificateEntry> result = new ArrayList<TrustedCertificateEntry>();
		for (TrustedCertificateEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getTrustedCertificate());
			byte[] createdPublicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(certificateHolder);
			if(Arrays.equals(createdPublicKeyIdentifier, issuerUIDBytes))
				result.add(entry);
		}
		return result;
	}

	private List<PrivateKeyEntry> filterContacts(
			List<PrivateKeyEntry> foundCertificates,
			AuthorityKeyIdentifier authorityKeyIdentifier) {
		if(authorityKeyIdentifier==null) return foundCertificates;
		List<PrivateKeyEntry> result = new ArrayList<PrivateKeyEntry>();
		byte[] searchInput = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(authorityKeyIdentifier);
		for (PrivateKeyEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getCertificate());
			byte[] asByteString = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(certificateHolder);
			if(Arrays.equals(searchInput, asByteString))
				result.add(entry);
		}
		return result;
	}
	private List<TrustedCertificateEntry> filterContacts0(
			List<TrustedCertificateEntry> foundCertificates,
			AuthorityKeyIdentifier authorityKeyIdentifier) {
		if(authorityKeyIdentifier==null) return foundCertificates;
		List<TrustedCertificateEntry> result = new ArrayList<TrustedCertificateEntry>();
		byte[] searchInput = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(authorityKeyIdentifier);
		for (TrustedCertificateEntry entry : foundCertificates) {
			X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(entry.getTrustedCertificate());
			byte[] asByteString = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(certificateHolder);
			if(Arrays.equals(searchInput, asByteString))
				result.add(entry);
		}
		return result;
	}
	
	private List<PrivateKeyEntry> filterPrivateKeyContacts(List<PrivateKeyEntry> foundEntries, PurposeEnum purpose){
		if(purpose==null) return foundEntries;
		List<PrivateKeyEntry> result = new ArrayList<PrivateKeyEntry>();
		for (PrivateKeyEntry privateKeyEntry : foundEntries) {
			if(purpose==PurposeEnum.CA && V3CertificateUtils.isCaKey(privateKeyEntry.getCertificate())){
				result.add(privateKeyEntry);
			} else if(purpose==PurposeEnum.ME && V3CertificateUtils.isSmimeKey(privateKeyEntry.getCertificate())){
				result.add(privateKeyEntry);
			}
		}
		return result;
	}
	private List<TrustedCertificateEntry> filterCertContacts(List<TrustedCertificateEntry> foundEntries, PurposeEnum purpose){
		if(purpose==null) return foundEntries;
		List<TrustedCertificateEntry> result = new ArrayList<TrustedCertificateEntry>();
		for (TrustedCertificateEntry trustedCertificateEntry : foundEntries) {
			if(purpose==PurposeEnum.CA && V3CertificateUtils.isCaKey(trustedCertificateEntry.getTrustedCertificate())){
				result.add(trustedCertificateEntry);
			} else if(purpose==PurposeEnum.ME && V3CertificateUtils.isSmimeKey(trustedCertificateEntry.getTrustedCertificate())){
				result.add(trustedCertificateEntry);
			}
		}
		return result;
	}
}
