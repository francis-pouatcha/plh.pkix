package org.adorsys.plh.pkix.core.test.cmp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
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

	private BlockingQueue<String> issuedCertBlockingQueue = new ArrayBlockingQueue<String>(100);
	private List<String> expectedIssuedCertificates = new ArrayList<String>();
	
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
	public void expectIssuedCertficate(String email){
		expectedIssuedCertificates.add(email);
	}
	
	@Override
	public void issuedCertificateImported(X509CertificateHolder certHolder) {
		List<String> issuerEmails = X500NameHelper.readIssuerEmails(certHolder);
		for (String email : issuerEmails) {
			issuedCertBlockingQueue.offer(email);
		}
	}


	public void waitForIssuedCertificates(){
		while(true){
			if(expectedIssuedCertificates.isEmpty()) return;
			try {
				String email = issuedCertBlockingQueue.take();
				expectedIssuedCertificates.remove(email);
			} catch (InterruptedException e) {
				// noop
			}
		}
	}
}
