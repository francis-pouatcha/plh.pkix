package org.adorsys.plh.pkix.core.smime.plooh;

public class SelectedFileNotADirectoryException extends Exception {

	private static final long serialVersionUID = 7581915375413813936L;

	public SelectedFileNotADirectoryException(String accountDirPath) {
		super(accountDirPath);
	}

}
