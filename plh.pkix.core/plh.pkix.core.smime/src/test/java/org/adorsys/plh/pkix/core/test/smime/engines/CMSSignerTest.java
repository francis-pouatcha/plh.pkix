package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;

import org.adorsys.plh.pkix.core.smime.engines.CMSPart;
import org.adorsys.plh.pkix.core.smime.engines.CMSSigner;
import org.adorsys.plh.pkix.core.smime.engines.CMSVerifier;
import org.adorsys.plh.pkix.core.utils.store.CMSSignedMessageValidator;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

public class CMSSignerTest {
	private static final File testDir = new File("target/"+CMSSignerTest.class.getSimpleName());

	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}

	@Test
	public void test() throws Exception {
		PrivateKeyEntryFactory privateKeyEntryFactory = new PrivateKeyEntryFactory(testDir);
		PrivateKeyEntry privateKeyEntry = privateKeyEntryFactory.getPrivateKeyEntry();

		File inputFile = new File("src/test/resources/rfc4210.pdf");		
		CMSPart inputPart = CMSPart.instanceFrom(inputFile);
		CMSPart outputPart = new CMSSigner()
			.withInputPart(inputPart)
			.sign(privateKeyEntry);
		inputPart.dispose();
		
		File signedOut = new File("target/rfc4210.pdf.testSignVerify.signed");
		outputPart.writeTo(signedOut);
		outputPart.dispose();
		
		CMSPart verifiedPartIn = CMSPart.instanceFrom(signedOut);
		CMSSignedMessageValidator<CMSPart> validator = new CMSVerifier()
			.withContactManager(privateKeyEntryFactory.getContactManager())
			.withInputPart(verifiedPartIn)
			.readAndVerify();
		
		CMSPart verifiedPartOut = validator.getContent();
		File verifiedOut = new File("target/rfc4210.pdf.testSignVerify.verified");
		verifiedPartOut.writeTo(verifiedOut);
		verifiedPartIn.dispose();
		verifiedPartOut.dispose();

		Assert.assertTrue(FileUtils.contentEquals(inputFile, verifiedOut));
		
		FileCleanup.deleteQuietly(signedOut,verifiedOut);
	}

}
