package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.smime.engines.CMSDecryptorVerifier;
import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.smime.engines.CMSSignerEncryptor;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

public class CMSSignerEncryptorTest {
	private static final File testDir = new File("target/"+CMSSignerEncryptorTest.class.getSimpleName());
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
		CMSPart signedEncryptedPartOut = new CMSSignerEncryptor()
			.withInputPart(inputPart)
			.withRecipientCertificates(Arrays.asList(x509Certificate))
			.signEncrypt(privateKeyEntry);
		inputPart.dispose();

		File signedEncryptedFile = new File("target/rfc4210.pdf.CMSSignerEncryptorTest.signed.encrypted");
		signedEncryptedPartOut.writeTo(signedEncryptedFile);
		signedEncryptedPartOut.dispose();
		
		
		// make sure the signed and encrypted content stream is different from original.
		Assert.assertFalse(FileUtils.contentEquals(inputFile, signedEncryptedFile));

		CMSPart signedEncryptedPartIn = CMSPart.instanceFrom(signedEncryptedFile);

		CMSSignedMessageValidator<CMSPart> validator = new CMSDecryptorVerifier()
			.withInputPart(signedEncryptedPartIn)
			.withContactManager(privateKeyEntryFactory.getContactManager())
			.decryptVerify();
		signedEncryptedPartIn.dispose();
		
		CMSPart decryptedVerifiedPart = validator.getContent();
		
		File decryptedVerifiedFile = new File("target/rfc4210.pdf.CMSSignerEncryptorTest.decrypted.verified");
		decryptedVerifiedPart.writeTo(decryptedVerifiedFile);
		decryptedVerifiedPart.dispose();

		// make sure decrypted and verified file is equal to original.
		Assert.assertTrue(FileUtils.contentEquals(inputFile, decryptedVerifiedFile));
		
		FileCleanup.deleteQuietly(signedEncryptedFile, decryptedVerifiedFile);
	}

}
