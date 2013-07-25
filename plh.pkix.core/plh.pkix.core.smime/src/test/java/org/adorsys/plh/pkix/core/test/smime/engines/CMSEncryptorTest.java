package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSDecryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSEncryptor;
import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

public class CMSEncryptorTest {
	
	private static final File testDir = new File("target/"+CMSEncryptorTest.class.getSimpleName());
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

		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart encryptedPartOut = new CMSEncryptor()
			.withInputPart(inputPart)
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.encrypt();
		inputPart.dispose();
		
		File encryptedFile = new File("target/rfc4210.pdf.testEncryptDecrypt.encrypted");
		encryptedPartOut.writeTo(encryptedFile);
		encryptedPartOut.dispose();
		
		// make sure the encrypted content stream is different.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, encryptedFile));

		CMSPart encryptedPartIn = CMSPart.instanceFrom(encryptedFile);
		CMSPart decryptedPart = new CMSDecryptor()
			.withInputPart(encryptedPartIn)
			.withContactManager(privateKeyEntryFactory.getContactManager())
			.decrypt();
		encryptedPartIn.dispose();
		
		File decryptedFile = new File("target/rfc4210.pdf.testEncryptDecrypt.decrypted");
		decryptedPart.writeTo(decryptedFile);
		decryptedPart.dispose();
		Assert.assertTrue(FileUtils.contentEquals(
				inputFile, decryptedFile));
		
		FileCleanup.deleteQuietly(encryptedFile,decryptedFile);
	}

}
