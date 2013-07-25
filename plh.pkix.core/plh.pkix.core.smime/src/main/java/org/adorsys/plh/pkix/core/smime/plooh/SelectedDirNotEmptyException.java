package org.adorsys.plh.pkix.core.smime.plooh;

public class SelectedDirNotEmptyException extends Exception {

	private static final long serialVersionUID = -7197461734505688146L;

	public SelectedDirNotEmptyException(String accountDirPath) {
		super(accountDirPath);
	}

}
