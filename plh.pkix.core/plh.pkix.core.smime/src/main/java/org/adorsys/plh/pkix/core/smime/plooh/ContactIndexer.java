package org.adorsys.plh.pkix.core.smime.plooh;

import java.util.List;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;

public interface ContactIndexer {

	public ContactIndex getContactIndex();

	public void indexKeyStore(KeyStoreWraper keyStoreWraper, List<KeyStoreAlias> keyStoreAliases);

	public KeyStoreWraper loadKeyStore(String keyStoreId);
	
}
