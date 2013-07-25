package org.adorsys.plh.pkix.core.smime.utils;

import java.security.KeyStore.SecretKeyEntry;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeySelector;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;

public class SecretKeySelector {

	private ContactManager contactManager;
	private RecipientInformation recipient;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public SecretKeyEntry select(){
		checker.checkDirty()
			.checkNull(recipient, contactManager);

        RecipientId recipientId = recipient.getRID();

        if(!(recipientId instanceof KEKRecipientId))
        	return null;

		 List<KeyStoreAlias> allKeyStoreAliases = contactManager.keyStoreAliases();
		List<KeyStoreAlias> selectKeyStoreAliases = KeyStoreAlias.selectByPublicKeyIdentifier(allKeyStoreAliases, ((KEKRecipientId) recipientId).getKeyIdentifier(), SecretKeyEntry.class);
    	return contactManager.findEntryByAlias(SecretKeyEntry.class, selectKeyStoreAliases);
	}

	public SecretKeySelector withRecipientInformation(RecipientInformation recipientInformation) {
		this.recipient = recipientInformation;
		return this;
	}
	public SecretKeySelector withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
}
