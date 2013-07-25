package org.adorsys.plh.pkix.core.test.smime.engines;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.UUID;

import org.adorsys.plh.pkix.core.smime.plooh.ContactManagerImpl;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileWraper;
import org.bouncycastle.asn1.x500.X500Name;

public class PrivateKeyEntryFactory {
	private final ContactManager contactManager;
	private final PrivateKeyEntry privateKeyEntry;

	public PrivateKeyEntryFactory(File testDir) {
		X500Name subjectX500Name = X500NameHelper.makeX500Name("francis",
				"francis@plhtest.biz", UUID.randomUUID().toString(), UUID
						.randomUUID().toString());

		KeyStoreWraper keyStoreWraper = new KeyStoreWraper(
				new UnprotectedFileWraper("keystore", testDir),
				"private key password".toCharArray(),
				"Keystore password".toCharArray());
		new KeyPairBuilder().withEndEntityName(subjectX500Name)
				.withKeyStoreWraper(keyStoreWraper).build();

		contactManager = new ContactManagerImpl(keyStoreWraper);
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(null, null, null, null,
				null, KeyStoreAlias.PurposeEnum.ME, PrivateKeyEntry.class);
		privateKeyEntry = contactManager.findEntryByAlias(
				PrivateKeyEntry.class, keyStoreAlias);
	}

	public ContactManager getContactManager() {
		return contactManager;
	}

	public PrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}
}
