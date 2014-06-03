package org.adorsys.plh.pkix.core.client.contentbrowser;

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
public class ContentBrowserController {

	@Inject
	private MainView mainView;
	
	@Inject
	@NodeAddedEvent
	private Event<ContentBrowserItem> contentBrowserItemAddedEvent;
	
	@Inject
	@NodeRemovedEvent
	private Event<ContentBrowserItem> contentBrowserItemRemovedEvent;
	
	public void handleContentBrowserItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent ContentBrowserItem contentBrowserItem){
		Tab tab = contentBrowserItem.getTab();
		if(tab==null) return;
		TabPane contentBrowser = mainView.getContentBrowser();
		ObservableList<Tab> tabs = contentBrowser.getTabs();
		for (Tab n : tabs) {
			if(n.equals(tab)) return;
		}
		if(contentBrowserItem.getIndex()!=null){
			tabs.add(contentBrowserItem.getIndex(), tab);
		} else {
			tabs.add(tab);
		}
		contentBrowserItemAddedEvent.fire(new ContentBrowserItem(tab).setIndex(tabs.indexOf(tab)));
	}

	public void handleContentBrowserItemRemoveEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeRemoveEvent ContentBrowserItem contentBrowserItem){
		Tab tab = contentBrowserItem.getTab();
		if(tab==null) return;
		TabPane contentBrowser = mainView.getContentBrowser();
		ObservableList<Tab> tabs = contentBrowser.getTabs();
		int index = tabs.indexOf(tab);
		if(tabs.remove(tab)){
			contentBrowserItemRemovedEvent.fire(new ContentBrowserItem(tab).setIndex(index));
		}
	}
}
