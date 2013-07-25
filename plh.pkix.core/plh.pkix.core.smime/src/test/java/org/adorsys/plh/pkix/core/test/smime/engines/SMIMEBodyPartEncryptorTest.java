package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartEncryptor;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

public class SMIMEBodyPartEncryptorTest {
	private static final File testDir = new File("target/"+SMIMEBodyPartEncryptorTest.class.getSimpleName());

	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}

	@Test
	public void test() throws Exception {
		PrivateKeyEntryFactory privateKeyEntryFactory = new PrivateKeyEntryFactory(testDir);
		PrivateKeyEntry privateKeyEntry = privateKeyEntryFactory.getPrivateKeyEntry();
		X509CertificateHolder subjectCertificate = new X509CertificateHolder(privateKeyEntry.getCertificate().getEncoded());
		X509Certificate x509Certificate = V3CertificateUtils.getX509JavaCertificate(subjectCertificate);
		
		File inputFile = new File("src/test/resources/rfc4210.pdf");
        MimeBodyPart document = new MimeBodyPart();
        document.attachFile(inputFile);

        File encryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartEncryptorTest.test.encrypted");

		List<X509Certificate> recipientX509Certificates = Arrays.asList(x509Certificate);
		MimeBodyPart encryptedBodyPart = new SMIMEBodyPartEncryptor()
			.withMimeBodyPart(document)
			.withRecipientX509Certificates(recipientX509Certificates)
			.encrypt();
		
		FileOutputStream encryptOutputStream = new FileOutputStream(encryptedOutputFile);
		encryptedBodyPart.writeTo(encryptOutputStream);
		IOUtils.closeQuietly(encryptOutputStream);

		// make sure the encrypted content stream is different.
		Assert.assertFalse(FileUtils.contentEquals(
				inputFile, encryptedOutputFile));
		
		FileInputStream encryptedBodyPartInputStream = new FileInputStream(encryptedOutputFile);
		MimeBodyPart encryptedBodyPart2 = new MimeBodyPart(encryptedBodyPartInputStream);
		MimeBodyPart decryptedBodyPart2 = new SMIMEBodyPartDecryptor()
			.withContactManager(privateKeyEntryFactory.getContactManager())
			.withMimeBodyPart(encryptedBodyPart2)
			.decrypt();

		IOUtils.closeQuietly(encryptedBodyPartInputStream);
		
		File decryptedOutputFile =new File("target/rfc4210.pdf.SMIMEBodyPartEncryptorTest.test.derypted.pdf");
		decryptedBodyPart2.saveFile(decryptedOutputFile);

		Assert.assertTrue(FileUtils.contentEquals(inputFile,decryptedOutputFile));
		
	}

}
