package org.adorsys.plh.pkix.core.cmp.certann.sender;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
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
public class OutgoingCertAnnActionExecutor {

	// Receiver Information
	private X509CertificateHolder receiverCertificate;

	private String workflowId;    
	private CMPCertificate cmpCertificate;
	
	private final BuilderChecker checker = new BuilderChecker(OutgoingCertAnnActionExecutor.class);
    public PKIMessage build(PrivateKeyEntry senderPrivateKeyEntry) {
    	checker.checkDirty()
    		.checkNull(senderPrivateKeyEntry,workflowId, receiverCertificate);

		GeneralName recipientName = new GeneralName(X500NameHelper.readSubjectDN(receiverCertificate));
		
		List<X509CertificateHolder> senderCertificateChain = new ArrayList<X509CertificateHolder>();
		Certificate[] certificateChain = senderPrivateKeyEntry.getCertificateChain();
		for (Certificate certificate : certificateChain) {
			senderCertificateChain.add(V3CertificateUtils.getX509CertificateHolder(certificate));		
		}
		X509CertificateHolder senderCertificate = senderCertificateChain.get(0);
		X500Name subjectDN = X500NameHelper.readSubjectDN(senderCertificate);
		ContentSigner senderSigner = V3CertificateUtils.getContentSigner(senderPrivateKeyEntry.getPrivateKey(),"MD5WithRSAEncryption");
        byte[] publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(senderCertificate);
		byte[] recipKeyId = KeyIdUtils.createPublicKeyIdentifierAsByteString(receiverCertificate);
		
        ProtectedPKIMessage mainMessage;
		try {
			ProtectedPKIMessageBuilder b = new ProtectedPKIMessageBuilder(new GeneralName(subjectDN), recipientName)
			                                          .setBody(new PKIBody(PKIBody.TYPE_CERT_ANN, cmpCertificate))
			                                          .setMessageTime(new Date())
			                                          .setRecipKID(recipKeyId)
			                                          .setSenderKID(publicKeyIdentifier)
												      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
												      .setTransactionID(UUIDUtils.newUUIDAsBytes());

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

	public OutgoingCertAnnActionExecutor withReceiverCertificate(X509CertificateHolder receiverCertificate) {
		this.receiverCertificate = receiverCertificate;
		return this;
	}

	public OutgoingCertAnnActionExecutor withWorkflowId(String workflowId) {
		this.workflowId = workflowId;
		return this;
	}

	public OutgoingCertAnnActionExecutor withCmpCertificate(CMPCertificate cmpCertificate) {
		this.cmpCertificate = cmpCertificate;
		return this;
	}

}
