package org.adorsys.plh.pkix.core.utils.plooh;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactListener;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * A plooh account is an interface to the contact manager.
 * 
 * @author fpo
 * 
 */
public class PloohAccount {

	private ActionContext accountContext;
	private FileWrapper accountDir;

	public PloohAccount(FileWrapper accountDir, ActionContext accountContext) {
		this.accountContext = accountContext;
		this.accountDir = accountDir;
	}

	public ActionContext getAccountContext() {
		return accountContext;
	}

	public FileWrapper getAccountDir() {
		return accountDir;
	}

	public TrustedCertificateEntry findCaSigningCertificate(String caEndEntityId) {
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(caEndEntityId, null,
				null, null, null, KeyStoreAlias.PurposeEnum.CA,
				TrustedCertificateEntry.class);
		return contactManager.findEntryByAlias(TrustedCertificateEntry.class,
				keyStoreAlias);
	}

	public TrustedCertificateEntry findMessagingCertificateByEmail(
			String endEntityId) {
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		KeyStoreAlias keyStoreAlias = new KeyStoreAlias(endEntityId, null,
				null, null, null, KeyStoreAlias.PurposeEnum.ME,
				TrustedCertificateEntry.class);
		return contactManager.findEntryByAlias(TrustedCertificateEntry.class,
				keyStoreAlias);
	}

	public void addContactListener(ContactListener contactListener) {
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		contactManager.addContactListener(contactListener);
	}

	public List<PrivateKeyEntry> findAllMessagePrivateKeyEntriesByPublicKey(
			X509CertificateHolder certificateHolder) {
		ActionContext actionContext = new ActionContext(accountContext);
		ContactManager contactManager = actionContext.get(ContactManager.class);
		List<KeyStoreAlias> allKas = contactManager.keyStoreAliases();
		List<KeyStoreAlias> keyStoreAliases = KeyStoreAlias
				.selectByPublicKeyIdentifier(allKas,
						certificateHolder.getSubjectPublicKeyInfo(),
						PrivateKeyEntry.class);
		return contactManager.findEntriesByAlias(PrivateKeyEntry.class,
				keyStoreAliases);
	}
}
