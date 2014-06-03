package org.adorsys.plh.pkix.client.contact.signin;

import javax.annotation.PostConstruct;
import javax.enterprise.event.Event;
import javax.inject.Inject;

import javafx.scene.control.MenuItem;

import org.adorsys.plh.pkix.client.contact.menu.ContactMenuItem;
import org.adorsys.plh.pkix.core.client.cdi.Eager;
import org.adorsys.plh.pkix.core.client.event.NodeAddEvent;

@Eager
public class SignInController {

	private MenuItem signInMenuItem;
	private ContactMenuItem contactMenuItem;
	
	@Inject
	@NodeAddEvent
	private Event<ContactMenuItem> addSignInMenuItem;
	
	@PostConstruct
	public void postConstruct(){
		signInMenuItem = new MenuItem("sign In");
		contactMenuItem = new ContactMenuItem(signInMenuItem);
		addSignInMenuItem.fire(contactMenuItem);
	}
}
