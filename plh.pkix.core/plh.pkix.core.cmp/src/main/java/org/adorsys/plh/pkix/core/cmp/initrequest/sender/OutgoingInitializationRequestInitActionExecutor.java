package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.initrequest.InitRequestMessages;
import org.adorsys.plh.pkix.core.cmp.stores.CMPRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequests;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentSigner;

/**
 * Builds an certificate request.
 * 
 * @author francis
 * 
 */
public class OutgoingInitializationRequestInitActionExecutor {

	private static final Random rnd = new Random();

	// Receiver Information
	private String receiverEmail;
	private X509CertificateHolder receiverCertificate;

	// Certificate information
	private boolean ca;
	private boolean caSet;

	private X500Name subjectDN;

	private SubjectPublicKeyInfo subjectPublicKeyInfo;

	private Date notBefore;

	private Date notAfter;

	private int keyUsage = -1;
	private boolean keyUsageSet = false;

	private GeneralNames subjectAltNames;

	private X500Name certAuthorityName;
	
	private String workflowId;

	private final BuilderChecker checker = new BuilderChecker(
			OutgoingInitializationRequestInitActionExecutor.class);

	public CMPRequest build(PrivateKeyEntry senderPrivateKeyEntry, ActionContext actionContext) {
    	checker.checkDirty()
    		.checkNull(senderPrivateKeyEntry, workflowId);
    	
		CertTemplateBuilder builder = new CertTemplateBuilder();

		if(subjectDN!=null)
			builder = builder.setSubject(subjectDN);
		
		if(certAuthorityName!=null)
			builder = builder.setIssuer(certAuthorityName);
		
		if(subjectPublicKeyInfo!=null)
			builder = builder.setPublicKey(subjectPublicKeyInfo);

		if(notBefore!=null && notAfter!=null){
			OptionalValidity optionalValidity = new OptionalValidityHolder(notBefore,notAfter).getOptionalValidity();
			builder = builder.setValidity(optionalValidity);
		}
					
		BasicConstraints basicConstraints = null;
		if(caSet)
			if(ca){
				basicConstraints = new BasicConstraints(true);
			} else {
				basicConstraints = new BasicConstraints(false);
			}
		
		ExtensionsGenerator extGenerator = new ExtensionsGenerator();
		try {
			if(basicConstraints!=null)extGenerator.addExtension(X509Extension.basicConstraints,true, basicConstraints);
			
			if(keyUsageSet){
				extGenerator.addExtension(X509Extension.keyUsage,
						true, new KeyUsage(this.keyUsage));
			}
			// complex rules for subject alternative name. See rfc5280
			if(subjectAltNames!=null){
				extGenerator.addExtension(X509Extension.subjectAlternativeName, true, subjectAltNames);
			}
		} catch(IOException e){
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		CertRequestMessages.CertRequestMessages_generate_errorBuildingExtention,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
		builder = builder.setExtensions(extGenerator.generate());
		
		CertTemplate certTemplate = builder.build();
		
		BigInteger probablePrime = BigInteger.probablePrime(9, rnd);
		ASN1Integer certReqId = new ASN1Integer(probablePrime);
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, null);
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});

		GeneralName recipientName = null;
		if(receiverCertificate!=null){
			recipientName = new GeneralName(X500NameHelper.readSubjectDN(receiverCertificate));
		}else if (receiverEmail!=null){
			recipientName = X500NameHelper.makeSubjectAlternativeName(receiverEmail);
		} else {
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		InitRequestMessages.InitRequestMessages_ui_missingRecipient);
            throw new PlhUncheckedException(msg);
		}
		
		List<X509CertificateHolder> senderCertificateChain = new ArrayList<X509CertificateHolder>();
		Certificate[] certificateChain = senderPrivateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			senderCertificateChain.add(V3CertificateUtils.getX509CertificateHolder(certificate));		
		}
		X509CertificateHolder senderCertificate = senderCertificateChain.get(0);
		X500Name subjectDN = X500NameHelper.readSubjectDN(senderCertificate);
		ContentSigner senderSigner = V3CertificateUtils.getContentSigner(senderPrivateKeyEntry.getPrivateKey(),"MD5WithRSAEncryption");
        byte[] publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(senderCertificate);
		
        ProtectedPKIMessage mainMessage;
		try {
			ProtectedPKIMessageBuilder b = new ProtectedPKIMessageBuilder(new GeneralName(subjectDN), recipientName)
			                                          .setBody(new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages))
			                                          .setMessageTime(new Date())
			                                          .setSenderKID(publicKeyIdentifier)
												      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
												      .setTransactionID(UUIDUtils.newUUIDAsBytes());
			if(receiverCertificate!=null){
				byte[] recipKeyId = KeyIdUtils.createPublicKeyIdentifierAsByteString(receiverCertificate);
				b = b.setRecipKID(recipKeyId);
			}
			for (X509CertificateHolder certHolder : senderCertificateChain) {
				b = b.addCMPCertificate(certHolder);
			}
			mainMessage = b.build(senderSigner);
		} catch (CMPException e) {
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		CertRequestMessages.CertRequestMessages_generate_generalCMPException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}

		OutgoingRequests cmpRequests = actionContext.get(OutgoingRequests.class);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		CMPRequest initializationRequest = 
				new CMPRequest(pkiMessage.getHeader().getTransactionID(), 
						new DERGeneralizedTime(new Date()), new ASN1Integer(PKIBody.TYPE_INIT_REQ), new DERUTF8String(workflowId));
		cmpRequests.newRequest(initializationRequest);
		cmpRequests.setRequest(initializationRequest, pkiMessage);

		return initializationRequest;
	}

	public OutgoingInitializationRequestInitActionExecutor withCa(boolean ca) {
		this.ca = ca;
		this.caSet = true;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withKeyUsage(int keyUsage) {
		if (keyUsageSet) {
			this.keyUsage = this.keyUsage | keyUsage;
		} else {
			this.keyUsage = keyUsage;
			keyUsageSet = true;
		}
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withSubjectDN(
			X500Name subjectDN) {
		this.subjectDN = subjectDN;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withSubjectPublicKeyInfo(
			SubjectPublicKeyInfo subjectPublicKeyInfo) {
		this.subjectPublicKeyInfo = subjectPublicKeyInfo;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withNotBefore(Date notBefore) {
		this.notBefore = notBefore;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withNotAfter(Date notAfter) {
		this.notAfter = notAfter;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withSubjectAltNames(
			GeneralNames subjectAltNames) {
		this.subjectAltNames = subjectAltNames;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withCertAuthorityName(
			X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withReceiverEmail(String receiverEmail) {
		this.receiverEmail = receiverEmail;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withReceiverCertificate(X509CertificateHolder receiverCertificate) {
		this.receiverCertificate = receiverCertificate;
		return this;
	}

	public OutgoingInitializationRequestInitActionExecutor withWorkflowId(String workflowId) {
		this.workflowId = workflowId;
		return this;
	}	
	
	
}
