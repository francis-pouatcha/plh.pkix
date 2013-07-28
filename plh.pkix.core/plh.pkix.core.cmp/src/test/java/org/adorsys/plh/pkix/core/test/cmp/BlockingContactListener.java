package org.adorsys.plh.pkix.core.test.cmp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Used to synchronize work flows.
 * 
 * @author fpo
 *
 */
public class BlockingContactListener implements ContactListener {
	
	private BlockingQueue<String> contactBlockingQueue = new ArrayBlockingQueue<String>(100);
	private List<String> expectedContacts = new ArrayList<String>();

	private BlockingQueue<String> issuedCertBlockingQueue = new ArrayBlockingQueue<String>(100);
	private List<String> expectedIssuedCertificates = new ArrayList<String>();
	
	@Override
	public void contactAdded(X509CertificateHolder certHolder) {
		String publicKeyIdentifierHex = KeyIdUtils.createPublicKeyIdentifierAsString(certHolder);
		contactBlockingQueue.offer(publicKeyIdentifierHex);
	}
	
	/**
	 * Expect a contact whose certificate carries the following email.
	 * @param email
	 */
	public void expectContact(String publicKeyIdentifierHex){
		expectedContacts.add(publicKeyIdentifierHex);
	}


	public void waitForContacts(){
		while(true){
			if(expectedContacts.isEmpty()) return;
			try {
				String publicKeyIdentifierHex = contactBlockingQueue.take();
				expectedContacts.remove(publicKeyIdentifierHex);
			} catch (InterruptedException e) {
				// noop
			}
		}
	}

	
	/**
	 * Expect a issued certificate whose ca carries the following email.
	 * @param email
	 */
	public void expectIssuedCertficate(String authorityKeyIdentifierHex){
		expectedIssuedCertificates.add(authorityKeyIdentifierHex);
	}
	
	@Override
	public void issuedCertificateImported(X509CertificateHolder certHolder) {
		String authorityKeyIdentifierHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(certHolder);
		issuedCertBlockingQueue.offer(authorityKeyIdentifierHex);
	}


	public void waitForIssuedCertificates(){
		while(true){
			if(expectedIssuedCertificates.isEmpty()) return;
			try {
				String authorityKeyIdentifierHex = issuedCertBlockingQueue.take();
				expectedIssuedCertificates.remove(authorityKeyIdentifierHex);
			} catch (InterruptedException e) {
				// noop
			}
		}
	}
}
