package org.adorsys.plh.pkix.core.client;

import java.io.File;

import org.adorsys.plh.pkix.core.smime.plooh.AccountManagerFactory;
import org.adorsys.plh.pkix.core.smime.plooh.FileContainerFactory;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;

/**
 * This class represent the plooh user instance as defined in the {@link PloohClient}.
 * 
 * @author fpo
 *
 */
public final class PloohUserInstance {

	private final FilesContainer filesContainer;
//	private FilesContainer userDir;

	public PloohUserInstance(File containerDir, char[] containerKeyPass, char[] containerStorePass) {
		filesContainer = FileContainerFactory.loadOrCreateFilesContainer(containerDir, containerKeyPass, containerStorePass);
		load();// load registered accounts
	}
}
