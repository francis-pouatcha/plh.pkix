package org.adorsys.plh.pkix.core.client.menubar;

import javafx.collections.ObservableList;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;

import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.enterprise.event.Reception;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.adorsys.plh.pkix.core.client.MainView;
import org.adorsys.plh.pkix.core.client.event.NodeAddEvent;
import org.adorsys.plh.pkix.core.client.event.NodeAddedEvent;
import org.adorsys.plh.pkix.core.client.event.NodeRemoveEvent;
import org.adorsys.plh.pkix.core.client.event.NodeRemovedEvent;

@Singleton
public class MenuBarController {

	@Inject
	private MainView mainView;
	
	@Inject
	@NodeAddedEvent
	private Event<MenuBarItem> menuBarItemAddedEvent;
	
	@Inject
	@NodeRemovedEvent
	private Event<MenuBarItem> menuBarItemRemovedEvent;
	
	public void handleMenuBarItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent MenuBarItem menuBarItem){
		Menu menu = menuBarItem.getMenu();
		if(menu==null) return;
		MenuBar menuBar = mainView.getMenuBar();
		ObservableList<Menu> menus = menuBar.getMenus();
		for (Menu n : menus) {
			if(n.equals(menu)) return;
		}
		if(menuBarItem.getIndex()!=null){
			menus.add(menuBarItem.getIndex(), menu);
		} else {
			menus.add(menu);
		}
		menuBarItemAddedEvent.fire(new MenuBarItem(menu).setIndex(menus.indexOf(menu)));
	}

	public void handleMenuBarItemRemoveEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeRemoveEvent MenuBarItem menuBarItem){
		Menu menu = menuBarItem.getMenu();
		if(menu==null) return;
		MenuBar menuBar = mainView.getMenuBar();
		ObservableList<Menu> menus = menuBar.getMenus();
		int index = menus.indexOf(menu);
		if(menus.remove(menu)){
			menuBarItemRemovedEvent.fire(new MenuBarItem(menu).setIndex(index));
		}
	}
}
