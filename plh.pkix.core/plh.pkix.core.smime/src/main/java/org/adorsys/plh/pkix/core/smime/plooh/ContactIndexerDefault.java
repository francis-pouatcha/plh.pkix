package org.adorsys.plh.pkix.core.smime.plooh;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public class ContactIndexerDefault implements ContactIndexer {
	// The cache. TODO replace with clean cache.
	// The key is the keyStoreId, or the relative file name of the 
	// keyStore in the scope of the FileContainer.
	private final Map<String, KeyStoreWraper> contacts = new HashMap<String, KeyStoreWraper>();
	
	private final FileWrapper contactsDir;

	private ContactIndex contactIndex;	
	private EmailContactIndexer emailContactIndexer;

	public ContactIndexerDefault(FileWrapper contactsDir) {
		this.contactsDir = contactsDir;
		rescan();
	}

	public ContactIndex getContactIndex() {
		return contactIndex;
	}

	private void rescan(){
		contacts.clear();
		contactIndex = new ContactIndex();
		emailContactIndexer = new EmailContactIndexer();
		String[] list = contactsDir.list();
		if(list==null || list.length==0) return;
		for (String keyStoreId : list) {
			KeyStoreWraper keyStoreWraper = loadKeyStore(keyStoreId);
			indexKeyStore(keyStoreWraper,null);
		}
	}

	public void indexKeyStore(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases){
		if(keyStoreAliases==null)keyStoreAliases = keyStoreWraper.keyStoreAliases();
		for (KeyStoreAlias keyStoreAlias : keyStoreAliases) {
			getContactIndex().addContact(keyStoreWraper.getKeyStoreId(), keyStoreAlias);
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
		KeyStoreWraper keyStoreWraper = contacts.get(keyStoreId);
		if(keyStoreWraper!=null) return keyStoreWraper;		
		
		FileWrapper keyStoreFile = contactsDir.newChild(keyStoreId);
		keyStoreWraper = new KeyStoreWraper(keyStoreFile, null, contactsDir.getKeyStoreWraper().getKeyStoreId().toCharArray());
		if(keyStoreWraper!=null)
			contacts.put(keyStoreId, keyStoreWraper);
		return keyStoreWraper;
	}
	
	@Override
	public int contactCount(){
		if(!contactsDir.exists()) return 0;
		String[] list = contactsDir.list();
		if(list==null) return 0;
		return list.length;
	}
	
}
