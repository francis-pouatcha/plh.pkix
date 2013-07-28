package org.adorsys.plh.pkix.core.cmp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

/**
 * Test cmp messenger.
 * 
 * Holds a request and response queue for each end entity. Uses the sender's public
 * key identifier to identify the sender. Note that a sender can have many certificates.
 * 
 * @author francis
 *
 */
public class InMemoryCMPMessenger implements CMPMessenger {

	/**
	 * The endpoint map
	 */
	private Map<String, CMPMessageEndpoint> publicKeyIdentifier2EndPoint = new HashMap<String, CMPMessageEndpoint>();
	// associates email with end entity identifier.
	
	@Override
	public void send(PKIMessage pkiMessage) {
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(new GeneralPKIMessage(pkiMessage));
		verifyMessage(protectedPKIMessage);
		PKIHeader header = protectedPKIMessage.getHeader();
		ASN1OctetString recipKID = header.getRecipKID();
		CMPMessageEndpoint cmpMessageEndpoint = null;
		
		String recipientPublicKeyIdentifier = null;
		if(recipKID!=null){		
			recipientPublicKeyIdentifier = KeyIdUtils.hexEncode(recipKID.getOctets());
			cmpMessageEndpoint = publicKeyIdentifier2EndPoint.get(recipientPublicKeyIdentifier);
			if(cmpMessageEndpoint==null)
				throw new IllegalArgumentException("Recipient with public key id : " +recipientPublicKeyIdentifier+ " not found");
		} else {
			throw new IllegalArgumentException("Recipient with public key id : " +recipientPublicKeyIdentifier+ " not found");			
		}

		cmpMessageEndpoint.receive(pkiMessage);
	}

	@Override
	public synchronized void registerMessageEndPoint(CMPMessageEndpoint endpoint,
			PKIMessage initRequest) 
	{
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(new GeneralPKIMessage(initRequest));
		verifyMessage(protectedPKIMessage);

		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		if(certificates.length<1)
			throw new IllegalStateException("No certificate sent with registration request.");
		
		X509CertificateHolder subjectCertificate = certificates[0];
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectCertificate);
		X500Name subjectDN = X500NameHelper.readSubjectDN(subjectCertificate);
		System.out.println(subjectDN +":" +publicKeyIdentifier);
		if(publicKeyIdentifier2EndPoint.containsKey(publicKeyIdentifier))
			throw new IllegalStateException("Sender with key id exists");
		
		publicKeyIdentifier2EndPoint.put(publicKeyIdentifier, endpoint);
		
		List<RegisterMessageEndpointListener> registerMessageEndpointListeners2 = registerMessageEndpointListeners;
		for (RegisterMessageEndpointListener registerMessageEndpointListener : registerMessageEndpointListeners2) {
			registerMessageEndpointListener.newMessageEndpoint(publicKeyIdentifier);
		}
		
	}

	private void verifyMessage(ProtectedPKIMessage protectedPKIMessage) {
		// TODO Auto-generated method stub
		
	}

	List<RegisterMessageEndpointListener> registerMessageEndpointListeners = new ArrayList<RegisterMessageEndpointListener>();
	public void addRegisterMessageEndpointListener(RegisterMessageEndpointListener l){
		registerMessageEndpointListeners.add(l);
	}
}
