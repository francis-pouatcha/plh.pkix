package org.adorsys.plh.pkix.core.client.locale;

import java.util.Locale;

import javax.enterprise.inject.Produces;
import javax.inject.Singleton;

@Singleton
public class LocaleFactory {

	private Locale locale;

	public void setLocale(Locale l) {
		locale = l;
	}
	
	@Produces
    public Locale produceLocale() {
		if(locale!=null)
			return locale;
		return Locale.getDefault();
    }	
}
