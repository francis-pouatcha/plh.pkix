package org.adorsys.plh.pkix.core.smime.plooh;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartEncryptor;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEMessageSigner;
import org.adorsys.plh.pkix.core.smime.ports.CommunicationPort;
import org.adorsys.plh.pkix.core.smime.utils.FileWrapperDataSource;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.mail.smime.SMIMEException;

public class FileSender {

	private final List<FileWrapper> files = new ArrayList<FileWrapper>();
	private final List<EmailRecipient> recipients = new ArrayList<EmailRecipient>();

	private CommunicationPort communicationPort;
	private String subject;
	private String preferedSenderAddress;
	
	private final BuilderChecker checker = new BuilderChecker(SMIMEMessageSigner.class);
	
	public void sendFiles(PrivateKeyEntry privateKeyEntry) throws MessagingException, SMIMEException
	{
		Session session = communicationPort.getDefaultSession();
		
		checker.checkNull(communicationPort).checkDirty();

		if(files.isEmpty() || recipients.isEmpty()) return;

        MimeMessage mimeMessage = new MimeMessage(session);
        String from = readEmail(privateKeyEntry, preferedSenderAddress);
        mimeMessage.setFrom(new InternetAddress(from));

        List<InternetAddress> recipientList = new ArrayList<InternetAddress>(recipients.size());
        List<X509Certificate> recipientX509Certificates = new ArrayList<X509Certificate>(recipients.size());
        for (EmailRecipient emailRecipient : recipients) {
        	String recipientEmail = readEmail(emailRecipient);
        	recipientList.add(new InternetAddress(recipientEmail));
        	recipientX509Certificates.add(V3CertificateUtils.getX509JavaCertificate(emailRecipient.getCertificateHolder()));
		}
        InternetAddress[] addresses = recipientList.toArray(new InternetAddress[recipientList.size()]);
        mimeMessage.setRecipients(Message.RecipientType.TO, addresses);
        
        if(StringUtils.isNotBlank(subject))mimeMessage.setSubject(subject);
        
        MimeMultipart mimeMultipart = new MimeMultipart();
        
        for (FileWrapper fileWrapper : files) {
        	MimeBodyPart document = new MimeBodyPart();
            FileWrapperDataSource fwds = new FileWrapperDataSource(fileWrapper);
            document.setDataHandler(new DataHandler(fwds));
            document.setFileName(fileWrapper.getName());
            document.setHeader("Content-Type", "application/octet-stream");
            document.setHeader("Content-Transfer-Encoding", "binary");

    		MimeBodyPart encryptedBodyPart = new SMIMEBodyPartEncryptor()
				.withMimeBodyPart(document)
				.withRecipientX509Certificates(recipientX509Certificates)
				.encrypt();

    		mimeMultipart.addBodyPart(encryptedBodyPart);
		}
      
        mimeMessage.setContent(mimeMultipart);
        MimeMultipart signedMultipart = new SMIMEMessageSigner()
        	.withMimeMessage(mimeMessage)
        	.sign(privateKeyEntry);

        MimeMessage signedMessage = new MimeMessage(session);

        /* Set all original MIME headers in the signed message */
        @SuppressWarnings("rawtypes")
		Enumeration headers = mimeMessage.getAllHeaderLines();
        while (headers.hasMoreElements())
        {
            signedMessage.addHeaderLine((String)headers.nextElement());
        }
        /* Set the content of the signed message */
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        communicationPort.send(mimeMessage);
    }

	private String readEmail(PrivateKeyEntry privateKeyEntry,
			String preferedAddress) {
		Certificate certificate = privateKeyEntry.getCertificate();
		List<String> readSubjectEmails = X500NameHelper.readSubjectEmails(certificate);
		if(preferedAddress!=null){
			for (String email : readSubjectEmails) {
				if(StringUtils.equalsIgnoreCase(preferedAddress, email)) return email;
			}
		}
		return readSubjectEmails.iterator().next();
	}

	private String readEmail(EmailRecipient emailRecipient) {
		List<String> readSubjectEmails = X500NameHelper.readSubjectEmails(emailRecipient.getCertificateHolder());
		String preferedAddress = emailRecipient.getPreferredEmail();
		if(preferedAddress!=null){
			for (String email : readSubjectEmails) {
				if(StringUtils.equalsIgnoreCase(preferedAddress, email)) return email;
			}
		}
		return readSubjectEmails.iterator().next();
	}

	static {
        MailcapCommandMap mailcap = (MailcapCommandMap)CommandMap
                .getDefaultCommandMap();
        mailcap
        .addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");

        mailcap
		        .addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		mailcap
		        .addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		mailcap
		        .addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		mailcap
		        .addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
		
		CommandMap.setDefaultCommandMap(mailcap);
		
	}

	public FileSender setCommunicationPort(CommunicationPort communicationPort) {
		this.communicationPort = communicationPort;
		return this;
	}

	public FileSender setSubject(String subject) {
		this.subject = subject;
		return this;
	}

	public FileSender addFiles(List<FileWrapper> files) {
		this.files.addAll(files);
		return this;
	}

	public FileSender addFile(FileWrapper file) {
		this.files.add(file);
		return this;
	}
	
	public FileSender setPreferedSenderAddress(String preferedSenderAddress) {
		this.preferedSenderAddress = preferedSenderAddress;
		return this;
	}

	public FileSender addRecipients(List<EmailRecipient> recipients) {
		this.recipients.addAll(recipients);
		return this;
	}

	public FileSender addRecipient(EmailRecipient recipient) {
		this.recipients.add(recipient);
		return this;
	}
}
