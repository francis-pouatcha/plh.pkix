package org.adorsys.plh.pkix.client.contact.menu;

import javax.inject.Singleton;

import org.adorsys.plh.pkix.core.client.utils.menu.AbstractMenuController;

@Singleton
public class ContactMenuControler extends AbstractMenuController<ContactMenuItem>{

	@Override
	public String getMenuText() {
		return "contact";
	}
}
