package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Used to display a certification request and gather requestor feedback.
 * 
 * @author francis
 *
 */
public class CertificationRequestFieldHolder {

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
	
//	// the cert template. This is either the self signed certificate or
//	// A certificate issued by another authority.
//    private final X509CertificateHolder subjectPreCertificate;
    private final PrivateKeyEntry privateKeyEntryToCertify;
	
    // address of the receiver
    private X509CertificateHolder receiverCertificate;
    private String receiverEmail;
    
    public CertificationRequestFieldHolder(PrivateKeyEntry privateKeyEntryToCertify){
    	this.privateKeyEntryToCertify = privateKeyEntryToCertify;
    	X509CertificateHolder subjectPreCertificate = V3CertificateUtils.getX509CertificateHolder(privateKeyEntryToCertify.getCertificate());
    	
		Extension basicConstraintsExtension = subjectPreCertificate.getExtension(X509Extension.basicConstraints);
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		setCa(basicConstraints.isCA());

		subjectPublicKeyInfo=subjectPreCertificate.getSubjectPublicKeyInfo();
		subjectDN=subjectPreCertificate.getSubject();
		notBefore=subjectPreCertificate.getNotBefore();
		notAfter=subjectPreCertificate.getNotAfter();

		setKeyUsage(KeyUsageUtils.getKeyUsage(subjectPreCertificate));
		
		Extension extension = subjectPreCertificate.getExtension(X509Extension.subjectAlternativeName);
		if(extension!=null) subjectAltNames = GeneralNames.getInstance(extension.getParsedValue());
		
    }

	public boolean isCa() {
		return ca;
	}

	public void setCa(boolean ca) {
		this.ca = ca;
		this.caSet=true;
	}

	public boolean isCaSet() {
		return caSet;
	}

	public void setCaSet(boolean caSet) {
		this.caSet = caSet;
	}

	public X500Name getSubjectDN() {
		return subjectDN;
	}

	public void setSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
	}

	public boolean isSubjectOnlyInAlternativeName() {
		return subjectOnlyInAlternativeName;
	}

	public void setSubjectOnlyInAlternativeName(boolean subjectOnlyInAlternativeName) {
		this.subjectOnlyInAlternativeName = subjectOnlyInAlternativeName;
	}

	public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
		return subjectPublicKeyInfo;
	}

	public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
		this.subjectPublicKeyInfo = subjectPublicKeyInfo;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public int getKeyUsage() {
		return keyUsage;
	}

	public void setKeyUsage(int keyUsage) {
		this.keyUsage = keyUsage;
		this.keyUsageSet=true;
	}

	public boolean isKeyUsageSet() {
		return keyUsageSet;
	}

	public void setKeyUsageSet(boolean keyUsageSet) {
		this.keyUsageSet = keyUsageSet;
	}

	public GeneralNames getSubjectAltNames() {
		return subjectAltNames;
	}

	public void setSubjectAltNames(GeneralNames subjectAltNames) {
		this.subjectAltNames = subjectAltNames;
	}

	public X500Name getCertAuthorityName() {
		return certAuthorityName;
	}

	public void setCertAuthorityName(X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
	}
	
	public PrivateKeyEntry getPrivateKeyEntryToCertify() {
		return privateKeyEntryToCertify;
	}

	public X509CertificateHolder getReceiverCertificate() {
		return receiverCertificate;
	}

	public String getReceiverEmail() {
		return receiverEmail;
	}

	public void setReceiverCertificate(X509CertificateHolder receiverCertificate) {
		this.receiverCertificate = receiverCertificate;
	}

	public void setReceiverEmail(String receiverEmail) {
		this.receiverEmail = receiverEmail;
	}

	/**
	 * Returns a logical string identifier that can be used to identify this process instance.
	 * 
	 * @return
	 */
	public String getWorkflowId(){
		StringBuilder stringBuilder = new StringBuilder();
		
		String subjectWorkflowId = getSubjectWorkflowId();
		if(subjectWorkflowId!=null)stringBuilder.append(subjectWorkflowId);
		String certAuthWorkflowId = getCertAuthWorkflowId();
		if(certAuthWorkflowId!=null)stringBuilder.append(certAuthWorkflowId);
		String receiverWorkflowId = getReceiverWorkflowId();
		if(receiverWorkflowId!=null)stringBuilder.append(receiverWorkflowId);
		
		if(isCaSet())stringBuilder.append(ca);
		
		if(isKeyUsageSet())stringBuilder.append(keyUsage);
		
		if(notBefore!=null)stringBuilder.append(notBefore.getTime());
		if(notAfter!=null)stringBuilder.append(notAfter.getTime());
		
		return stringBuilder.toString();
	}

	private String getSubjectWorkflowId(){
		if(subjectPublicKeyInfo!=null) return KeyIdUtils.createPublicKeyIdentifierAsString(subjectPublicKeyInfo);
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(subjectAltNames, subjectDN);
		if(subjectEmails!=null && !subjectEmails.isEmpty()){
			StringBuilder result = new StringBuilder();		
			for (String email : subjectEmails) {
				result.append(email);
			}
			return result.toString();
		}
		return null;
	}
	
	private String getCertAuthWorkflowId(){
		if(certAuthorityName!=null){
			return certAuthorityName.toString();
		}
		return null;
	}
	
	private String getReceiverWorkflowId(){
		if(receiverCertificate!=null) {
			List<String> receiverEmails = X500NameHelper.readSubjectEmails(receiverCertificate);
			if(receiverEmails!=null && receiverEmails.isEmpty()){
				StringBuilder result = new StringBuilder();		
				for (String email : receiverEmails) {
					result.append(email);
				}
				return result.toString();
			}
		}
		if(receiverEmail!=null){
			return receiverEmail.toLowerCase();
		}
		return null;
	}
}
