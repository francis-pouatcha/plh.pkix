package org.adorsys.plh.pkix.core.cmp.certrequest.ca;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias.PurposeEnum;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.PublicKeyUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertificateChain;
import org.adorsys.plh.pkix.core.utils.jca.X509CertificateBuilder;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Uses the ca private key of the certification authority to create a certificate and 
 * return it with the corresponding certificate chain.
 * 
 * @author francis
 *
 */
public class CertReqCertifyActionExecutor {
	
	private CertTemplate certTemplate;
	
	private final BuilderChecker checker = new BuilderChecker(CertReqCertifyActionExecutor.class);
	public ASN1CertificateChain execute(ActionContext actionContext){
		checker.checkDirty().checkNull(certTemplate,actionContext);
		
		UserAccount userAccount = actionContext.get(UserAccount.class);		
		checker.checkNull(userAccount);

		
		PrivateKeyEntry privateKeyEntry = null;
		// If the issuer field is not null, try to find the ca certificate with the given issuer
		// We will have to ignore the issuer field. Is not deterministic.
		AuthorityKeyIdentifier authorityKeyIdentifier = KeyIdUtils.readAuthorityKeyIdentifier(certTemplate);
		if(authorityKeyIdentifier!=null){
			String authorityKeyIdentifierHex = KeyIdUtils.authorityKeyIdentifierToString(authorityKeyIdentifier);

			// then search by public key identifier
			KeyStoreAlias keyStoreAliasByPublicKeyIdentifier = new KeyStoreAlias(authorityKeyIdentifierHex, null, null, PurposeEnum.CA, PrivateKeyEntry.class);
			List<PrivateKeyEntry> privateKeys = userAccount.findPrivateKeys(keyStoreAliasByPublicKeyIdentifier);
			
			if(privateKeys!=null&&privateKeys.size()>0)
				privateKeyEntry = privateKeys.iterator().next();
		}
		
		if(privateKeyEntry==null){
			privateKeyEntry = userAccount.getAnyCaPrivateKeyEntry();
		}

		SubjectPublicKeyInfo subjectPublicKeyInfo = certTemplate.getPublicKey();
		PublicKey subjectPublicKey;
		try {
			subjectPublicKey = PublicKeyUtils.getPublicKey(subjectPublicKeyInfo, ProviderUtils.bcProvider);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}

		OptionalValidityHolder optionalValidityHolder = new OptionalValidityHolder(certTemplate.getValidity());
		Time notBefore = optionalValidityHolder.getNotBefore();
		Time notAfter = optionalValidityHolder.getNotAfter();
		X509CertificateHolder issuerCertificateHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
		
		X509CertificateBuilder certificateBuilder = new X509CertificateBuilder()
			.withIssuerCertificate(issuerCertificateHolder)
			.withNotAfter(notAfter.getDate())
			.withNotBefore(notBefore.getDate())
			.withSubjectDN(certTemplate.getSubject())
			.withSubjectPublicKey(subjectPublicKey);

		Extensions extensions = certTemplate.getExtensions();
		Extension basicConstraintsExtension = extensions.getExtension(X509Extension.basicConstraints);
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		boolean ca = basicConstraints.isCA();
		certificateBuilder = certificateBuilder.withCa(ca);

		Extension extension1 = extensions.getExtension(X509Extension.subjectAlternativeName);
		if(extension1!=null) {
			GeneralNames subjectAltName = GeneralNames.getInstance(extension1.getParsedValue());
			if(subjectAltName!=null)certificateBuilder = certificateBuilder.withSubjectAltNames(subjectAltName);
		}
		
		int keyUsage = KeyUsageUtils.getKeyUsage(extensions);
		if(keyUsage>-1){
			certificateBuilder = certificateBuilder.withKeyUsage(keyUsage);
		}
		
		Extension extension2 = extensions.getExtension(X509Extension.authorityInfoAccess);
		if(extension2!=null){
			AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(extension2.getParsedValue());
			if(authorityInformationAccess!=null)
				certificateBuilder = certificateBuilder.withAuthorityInformationAccess(authorityInformationAccess);
		}
		
		X509CertificateHolder x509CertificateHolder = certificateBuilder.build(privateKeyEntry.getPrivateKey());
		Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
		org.bouncycastle.asn1.x509.Certificate[] crts = new org.bouncycastle.asn1.x509.Certificate[certificateChain.length + 1];
		crts[0] = V3CertificateUtils.getX509BCCertificate(x509CertificateHolder);
		if(certificateChain!=null){
			for (int i = 0; i < certificateChain.length; i++) {
				crts[i+1] = V3CertificateUtils.getX509BCCertificate(certificateChain[i]);
			}
		}
		return new ASN1CertificateChain(crts);
	}
	public CertReqCertifyActionExecutor withCertTemplate(CertTemplate certTemplate) {
		this.certTemplate = certTemplate;
		return this;
	}
}
