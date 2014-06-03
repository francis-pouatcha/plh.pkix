package org.adorsys.plh.pkix.core.client.utils.menu;

import javafx.collections.ObservableList;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuItem;

import javax.annotation.PostConstruct;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.enterprise.event.Reception;
import javax.inject.Inject;

import org.adorsys.plh.pkix.core.client.event.NodeAddEvent;
import org.adorsys.plh.pkix.core.client.event.NodeAddedEvent;
import org.adorsys.plh.pkix.core.client.event.NodeRemoveEvent;
import org.adorsys.plh.pkix.core.client.event.NodeRemovedEvent;
import org.adorsys.plh.pkix.core.client.menubar.MenuBarItem;

public abstract class AbstractMenuController<T extends AbstractMenuItem> {

	protected MenuBarItem menubarItem;
	
	@Inject
	@NodeAddedEvent
	private Event<T> menuItemAddedEvent; 
	
	@Inject
	@NodeRemovedEvent
	private Event<T> menuItemRemovedEvent; 
	
	@Inject
	@NodeAddEvent
	private Event<MenuBarItem> menuAddEvent; 
	
	@Inject
	@NodeRemoveEvent
	private Event<MenuBarItem> menuRemoveEvent; 

	@PostConstruct
	public void postConstruct(){
		menubarItem = new MenuBarItem(new Menu(getMenuText()));
	}
	
	public abstract String getMenuText();
	
	public void handleMenuItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent T abstractMenuItem){
		if(menubarItem==null) return;
		MenuItem menuItem = abstractMenuItem.getMenuItem();
		ObservableList<MenuItem> items = menubarItem.getMenu().getItems();
		if(!items.contains(menuItem)){
			Integer index = abstractMenuItem.getIndex();
			if(index!=null){
				if(items.size()>index){
					items.add(index, menuItem);
				} else {
					items.add(menuItem);
				}
			} else {
				items.add(menuItem);
			}
			index = items.indexOf(menuItem);
			abstractMenuItem.setIndex(index);
			menuItemAddedEvent.fire(abstractMenuItem);
			menuAddEvent.fire(menubarItem);
		}
	}

	public void handleMenuItemRemoveEvent(@Observes @NodeRemoveEvent T abstractMenuItem){
		MenuItem menuItem = abstractMenuItem.getMenuItem();
		ObservableList<MenuItem> items = menubarItem.getMenu().getItems();
		int index = items.indexOf(menuItem);
		if(items.remove(menuItem)){
			abstractMenuItem.setIndex(index);
			menuItemRemovedEvent.fire(abstractMenuItem);
		}
		if(items.isEmpty()) 
			menuRemoveEvent.fire(menubarItem);
	}
}
