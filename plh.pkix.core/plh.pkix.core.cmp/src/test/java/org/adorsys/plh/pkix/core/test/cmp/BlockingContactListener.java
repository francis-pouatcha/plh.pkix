package org.adorsys.plh.pkix.core.test.cmp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Will block till all expected contacts are added to the corresponding account.
 * 
 * @author fpo
 *
 */
public class BlockingContactListener implements ContactListener {
	
	private BlockingQueue<String> contactBlockingQueue = new ArrayBlockingQueue<String>(100);
	private List<String> expectedEmails = new ArrayList<String>();

	private BlockingQueue<X500Name> issuedCertBlockingQueue = new ArrayBlockingQueue<X500Name>(100);
	private List<X500Name> expectedIssuedCertificates = new ArrayList<X500Name>();
	
	@Override
	public void contactAdded(X509CertificateHolder certHolder) {
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(certHolder);
		for (String email : subjectEmails) {
			contactBlockingQueue.offer(email);
		}
	}
	
	/**
	 * Expect a contact whose certificate carries the following email.
	 * @param email
	 */
	public void expectContact(String email){
		expectedEmails.add(email);
	}


	public void waitForContacts(){
		while(true){
			if(expectedEmails.isEmpty()) return;
			try {
				String email = contactBlockingQueue.take();
				expectedEmails.remove(email);
			} catch (InterruptedException e) {
				// noop
			}
		}
	}

	
	/**
	 * Expect a issued certificate whose ca carries the following email.
	 * @param email
	 */
	public void expectIssuedCertficate(X500Name issuerName){
		expectedIssuedCertificates.add(issuerName);
	}
	
	@Override
	public void issuedCertificateImported(X509CertificateHolder certHolder) {
		issuedCertBlockingQueue.offer(certHolder.getIssuer());
	}


	public void waitForIssuedCertificates(){
		while(true){
			if(expectedIssuedCertificates.isEmpty()) return;
			try {
				X500Name issuerName = issuedCertBlockingQueue.take();
				expectedIssuedCertificates.remove(issuerName);
			} catch (InterruptedException e) {
				// noop
			}
		}
	}
}
