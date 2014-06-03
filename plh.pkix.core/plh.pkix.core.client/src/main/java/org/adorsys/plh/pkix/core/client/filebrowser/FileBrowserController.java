package org.adorsys.plh.pkix.core.client.filebrowser;

import javafx.collections.ObservableList;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;

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
public class FileBrowserController {

	@Inject
	private MainView mainView;
	
	@Inject
	@NodeAddedEvent
	private Event<FileBrowserItem> fileBrowserItemAddedEvent;
	
	@Inject
	@NodeRemovedEvent
	private Event<FileBrowserItem> fileBrowserItemRemovedEvent;
	
	public void handleFileBrowserItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent FileBrowserItem fileBrowserItem){
		Tab tab = fileBrowserItem.getTab();
		if(tab==null) return;
		TabPane fileBrowser = mainView.getFileBrowser();
		ObservableList<Tab> tabs = fileBrowser.getTabs();
		for (Tab n : tabs) {
			if(n.equals(tab)) return;
		}
		if(fileBrowserItem.getIndex()!=null){
			tabs.add(fileBrowserItem.getIndex(), tab);
		} else {
			tabs.add(tab);
		}
		fileBrowserItemAddedEvent.fire(new FileBrowserItem(tab).setIndex(tabs.indexOf(tab)));
	}

	public void handleFileBrowserItemRemoveEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeRemoveEvent FileBrowserItem fileBrowserItem){
		Tab tab = fileBrowserItem.getTab();
		if(tab==null) return;
		TabPane fileBrowser = mainView.getFileBrowser();
		ObservableList<Tab> tabs = fileBrowser.getTabs();
		int index = tabs.indexOf(tab);
		if(tabs.remove(tab)){
			fileBrowserItemRemovedEvent.fire(new FileBrowserItem(tab).setIndex(index));
		}
	}
}
