package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1Integer;
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
import org.bouncycastle.asn1.x509.Extension;
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
 * Builds an initial certification request. The subject's environment generates a 
 * key pair, generates a self signed certificate and envelopes it into a 
 * certification request that is sent to the intended certification authority.
 * 
 * @author francis
 *
 */
public class CertificationRequestInitActionExecutor {

	private static final Random rnd = new Random();

	// Receiver Information
	private String receiverEmail;
	private X509CertificateHolder receiverCertificate;

	// Certificate information
	private boolean ca;
	private boolean caSet;

	private X500Name subjectDN;
	
	private boolean subjectOnlyInAlternativeName;

	private SubjectPublicKeyInfo subjectPublicKeyInfo;

	private Date notBefore;

	private Date notAfter;

	private int keyUsage=-1;
	private boolean keyUsageSet = false;

	private GeneralNames subjectAltNames;

    private X500Name certAuthorityName;
    
	private String workflowId;    
	
	private final BuilderChecker checker = new BuilderChecker(CertificationRequestInitActionExecutor.class);
    public PKIMessage build(PrivateKeyEntry subjectPrivateKeyEntry, PrivateKeyEntry senderPrivateKeyEntry) {
    	checker.checkDirty()
    		.checkNull(subjectPrivateKeyEntry,senderPrivateKeyEntry,workflowId);

    	Certificate subjecPreCertificate = subjectPrivateKeyEntry.getCertificate();    	
    	X509CertificateHolder subjectPreCertificateHolder=V3CertificateUtils.getX509CertificateHolder(subjecPreCertificate);
		if(subjectPublicKeyInfo==null) subjectPublicKeyInfo=subjectPreCertificateHolder.getSubjectPublicKeyInfo();
		if(subjectDN==null) subjectDN=subjectPreCertificateHolder.getSubject();
		if(notBefore==null) notBefore=subjectPreCertificateHolder.getNotBefore();
		if(notAfter==null) notAfter=subjectPreCertificateHolder.getNotAfter();
		
		if(!keyUsageSet)copyKeyUsage(subjectPreCertificateHolder);
		
		if(subjectAltNames==null){
			Extension extension = subjectPreCertificateHolder.getExtension(X509Extension.subjectAlternativeName);
			if(extension!=null) subjectAltNames = GeneralNames.getInstance(extension.getParsedValue());
		}
		
		if(!caSet){
			Extension basicConstraintsExtension = subjectPreCertificateHolder.getExtension(X509Extension.basicConstraints);
			BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
			withCa(basicConstraints.isCA());
		}

		OptionalValidity optionalValidity = new OptionalValidityHolder(notBefore,notAfter).getOptionalValidity();

		BasicConstraints basicConstraints = null;
		if(caSet)
			if(ca){
				// self signed ca certificate
				basicConstraints = new BasicConstraints(true);
				subjectOnlyInAlternativeName = false;// in ca case, subject must subject must be set
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
				if(subjectOnlyInAlternativeName){
					extGenerator.addExtension(X509Extension.subjectAlternativeName, true, subjectAltNames);
				} else {
					extGenerator.addExtension(X509Extension.subjectAlternativeName, false, subjectAltNames);
				}
			}
		} catch(IOException e){
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		CertRequestMessages.CertRequestMessages_generate_errorBuildingExtention,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
				
		CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder()
        	.setSubject(subjectDN)
        	.setPublicKey(subjectPublicKeyInfo)
        	.setValidity(optionalValidity)
        	.setExtensions(extGenerator.generate());
		if(certAuthorityName!=null)
			certTemplateBuilder= certTemplateBuilder.setIssuer(certAuthorityName);
        CertTemplate certTemplate = certTemplateBuilder.build();
		
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
            		CertRequestMessages.CertRequestMessages_ui_missingRecipient);
            throw new PlhUncheckedException(msg);
		}
		
		List<X509CertificateHolder> senderCertificateChain = new ArrayList<X509CertificateHolder>();
		Certificate[] certificateChain = senderPrivateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			senderCertificateChain.add(V3CertificateUtils.getX509CertificateHolder(certificate));		
		}
		X509CertificateHolder senderCertificate = senderCertificateChain.get(0);
		X500Name senderDN = X500NameHelper.readSubjectDN(senderCertificate);
		ContentSigner senderSigner = V3CertificateUtils.getContentSigner(senderPrivateKeyEntry.getPrivateKey(),"MD5WithRSAEncryption");
        byte[] publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(senderCertificate);
		
        ProtectedPKIMessage mainMessage;
		try {
			ProtectedPKIMessageBuilder b = new ProtectedPKIMessageBuilder(new GeneralName(senderDN), recipientName)
			                                          .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, certReqMessages))
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

		return mainMessage.toASN1Structure();
	}
	public CertificationRequestInitActionExecutor withCa(boolean ca) {
		this.ca = ca;
		this.caSet=true;
		return this;
	}

	public CertificationRequestInitActionExecutor withKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public CertificationRequestInitActionExecutor withSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
		return this;
	}
	public CertificationRequestInitActionExecutor withSubjectOnlyInAlternativeName(boolean subjectOnlyInAlternativeName) {
		this.subjectOnlyInAlternativeName = subjectOnlyInAlternativeName;
		return this;
	}
	public CertificationRequestInitActionExecutor withSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
		this.subjectPublicKeyInfo = subjectPublicKeyInfo;
		return this;
	}
	public CertificationRequestInitActionExecutor withNotBefore(Date notBefore) {
		this.notBefore = notBefore;
		return this;
	}
	public CertificationRequestInitActionExecutor withNotAfter(Date notAfter) {
		this.notAfter = notAfter;
		return this;
	}

	public CertificationRequestInitActionExecutor withSubjectAltNames(GeneralNames subjectAltNames) {
		this.subjectAltNames = subjectAltNames;
		return this;
	}

	public CertificationRequestInitActionExecutor withCertAuthorityName(X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
		return this;
	}

	public CertificationRequestInitActionExecutor withReceiverEmail(String receiverEmail) {
		this.receiverEmail = receiverEmail;
		return this;
	}

	public CertificationRequestInitActionExecutor withReceiverCertificate(X509CertificateHolder receiverCertificate) {
		this.receiverCertificate = receiverCertificate;
		return this;
	}

	public CertificationRequestInitActionExecutor withWorkflowId(String workflowId) {
		this.workflowId = workflowId;
		return this;
	}	
	
	private void copyKeyUsage(X509CertificateHolder issuerCertificate) {
		int ku = KeyUsageUtils.getKeyUsage(issuerCertificate);
		if(ku!=-1)withKeyUsage(ku);
	}
}
