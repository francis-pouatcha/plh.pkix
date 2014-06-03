package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.Test;

public class UserAccountTest {
	private static final File testDir = new File("target/"+UserAccountTest.class.getSimpleName());
	
	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}
	
	
	@Test
	public void test() throws CertificateException, KeyStoreException, PlhCheckedException, SelectedFileNotADirectoryException {
		DummyUserAccountFactory factory = new DummyUserAccountFactory(testDir);
		String userName = "francis";
		FileContainerCallbackHandler fileContainerCallbackHandler =factory. newFileContainerCallbackHandler(userName, "francis@mail.com");
		factory.newUserAccount(userName,fileContainerCallbackHandler);
		factory.loadUserAccount(userName,fileContainerCallbackHandler);
	}
	
	
}
