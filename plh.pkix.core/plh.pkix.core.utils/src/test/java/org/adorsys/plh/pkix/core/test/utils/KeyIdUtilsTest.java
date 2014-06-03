package org.adorsys.plh.pkix.core.test.utils;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileWraper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class KeyIdUtilsTest {
	private static final File testDir = new File("target/KeyIdUtilsTest");

	@BeforeClass
	public static void prepareTest(){
		if(testDir.exists()) testDir.delete();
	}
	
	@Test
	public void testGetSubjectKeyIdentifierAsByteString() throws NoSuchAlgorithmException, IOException {
		
		FileWrapper keyStoreFileWrapper = new UnprotectedFileWraper("testGetSubjectKeyIdentifierAsByteString", testDir);
		KeyStoreWraper keyStoreWraper = new KeyStoreWraper(keyStoreFileWrapper, "keyPass".toCharArray(), "storePass".toCharArray());
		X509CertificateHolder subjectCertificateHolder = new KeyPairBuilder().withEndEntityName(new X500Name("cn=test")).withKeyStoreWraper(keyStoreWraper).build();
		byte[] byteString = KeyIdUtils.readSubjectKeyIdentifierAsByteString(subjectCertificateHolder);
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		SubjectKeyIdentifier subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(subjectCertificateHolder.getSubjectPublicKeyInfo());
		Assert.assertArrayEquals(byteString, subjectKeyIdentifier.getKeyIdentifier());
	}
}
