package org.adorsys.plh.pkix.core.smime.plooh;

import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public class ContactIndexerBootStrap implements ContactIndexer {
	
	private final ContactIndex contactIndex = new ContactIndex();	
	private final EmailContactIndexer emailContactIndexer = new EmailContactIndexer();
	private final KeyStoreWraper mainKeyStoreWraper;

	public ContactIndexerBootStrap(KeyStoreWraper mainKeyStoreWraper) {
		this.mainKeyStoreWraper = mainKeyStoreWraper;
		// Process main
		indexKeyStore(mainKeyStoreWraper, null);
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
	}

	public void indexKeyStore(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		if(keyStoreAliases==null)keyStoreAliases = keyStoreWraper.keyStoreAliases();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			getContactIndex().addContact(keyStoreWraper.getKeyStoreId(),keyStoreAlias);
		}
		emailIndex(keyStoreWraper, keyStoreAliases);
	}
	
	private void emailIndex(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		emailContactIndexer.emailIndex(keyStoreWraper, keyStoreAliases);
	}

	public Set<String> findKeyStoreAliasesByEmail(String... emails){
		return emailContactIndexer.findKeyStoreAliasesByEmail(emails);
	}
	
	public KeyStoreWraper loadKeyStore(String keyStoreId){
		return mainKeyStoreWraper;
	}

	@Override
	public int contactCount() {
		return 0;
	}
	
}
