package org.adorsys.plh.pkix.core.smime.engines;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

public class SMIMEMessageSigner {

	private MimeMessage mimeMessage;
	
	private final BuilderChecker checker = new BuilderChecker(SMIMEMessageSigner.class);
	public MimeMultipart sign(PrivateKeyEntry senderPrivateKeyEntry)
			throws SMIMEException, MessagingException
	{
		checker.checkDirty()
			.checkNull(senderPrivateKeyEntry, mimeMessage);
		
		Certificate[] certificateChain = senderPrivateKeyEntry.getCertificateChain();
		List<X509Certificate> senderCertificateChain = V3CertificateUtils.convert(certificateChain);

		// create a CertStore containing the certificates we want carried
		// in the signature
		Store senderCertStore;
		try {
			senderCertStore = new JcaCertStore(senderCertificateChain);
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		}

		// create some smime capabilities in case someone wants to respond
		ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
		SMIMECapabilityVector caps = new SMIMECapabilityVector();

		caps.addCapability(SMIMECapability.dES_EDE3_CBC);
		caps.addCapability(SMIMECapability.rC2_CBC, 128);
		caps.addCapability(SMIMECapability.dES_CBC);

		X509Certificate senderCertificate = senderCertificateChain.get(0);
		signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

		signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(
                new IssuerAndSerialNumber(
                        new X500Name(((X509Certificate)certificateChain[0])
                                .getIssuerDN().getName()),
                        ((X509Certificate)certificateChain[0]).getSerialNumber())));

		// create the generator for creating an smime/signed message
		SMIMESignedGenerator gen = new SMIMESignedGenerator();

		// add a signer to the generator - this specifies we are using SHA1 and
		// adding the smime attributes above to the signed attributes that
		// will be generated as part of the signature. The encryption algorithm
		// used is taken from the key - in this RSA with PKCS1Padding
		try {
			gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
					.setProvider(ProviderUtils.bcProvider)
					.setSignedAttributeGenerator(new AttributeTable(signedAttrs))
					.build("SHA1withRSA", senderPrivateKeyEntry.getPrivateKey(), senderCertificate));
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		// add our pool of certs and cerls (if any) to go with the signature
		gen.addCertificates(senderCertStore);

		// extract the multipart object from the SMIMESigned object.
		try {
			return gen.generate(mimeMessage, ProviderUtils.bcProvider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public SMIMEMessageSigner withMimeMessage(MimeMessage mimeMessage) {
		this.mimeMessage = mimeMessage;
		return this;
	}
}
