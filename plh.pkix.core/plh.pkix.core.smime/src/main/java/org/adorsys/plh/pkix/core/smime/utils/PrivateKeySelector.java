package org.adorsys.plh.pkix.core.smime.utils;

import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeySelector;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;

public class PrivateKeySelector {

	private ContactManager contactManager;
	private RecipientInformation recipient;

	private BuilderChecker checker = new BuilderChecker(KeySelector.class);
	public PrivateKeyEntry select(){
		checker.checkDirty()
			.checkNull(recipient, contactManager);

        RecipientId recipientId = recipient.getRID();
        if(!(recipientId instanceof KeyTransRecipientId))
        	return null;
        	
        KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientId;
        byte[] subjectKeyIdentifier = keyTransRecipientId.getSubjectKeyIdentifier();
        List<KeyStoreAlias> allKeyStoreAliases = contactManager.keyStoreAliases();
        if(subjectKeyIdentifier!=null){
   		 	List<KeyStoreAlias> selectedKeyStoreAliases = KeyStoreAlias.selectByPublicKeyIdentifier(
   		 		allKeyStoreAliases, subjectKeyIdentifier, PrivateKeyEntry.class);
        	
        	PrivateKeyEntry pk = contactManager.findEntryByAlias(PrivateKeyEntry.class, selectedKeyStoreAliases);
        	if(pk!=null) return pk;
        }
        
        BigInteger serialNumber = keyTransRecipientId.getSerialNumber();
        List<KeyStoreAlias> selectedKeyStoreAliases = KeyStoreAlias.selectBySerialNumber(allKeyStoreAliases, serialNumber);
        return contactManager.findEntryByAlias(PrivateKeyEntry.class, selectedKeyStoreAliases);
	}

	public PrivateKeySelector withRecipientInformation(RecipientInformation recipientInformation) {
		this.recipient = recipientInformation;
		return this;
	}

	public PrivateKeySelector withContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
		return this;
	}
}
