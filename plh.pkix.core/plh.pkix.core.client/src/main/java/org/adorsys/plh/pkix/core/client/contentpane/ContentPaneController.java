package org.adorsys.plh.pkix.core.client.contentpane;

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
public class ContentPaneController {

	@Inject
	private MainView mainView;
	
	@Inject
	@NodeAddedEvent
	private Event<ContentPaneItem> contentPaneItemAddedEvent;
	
	@Inject
	@NodeRemovedEvent
	private Event<ContentPaneItem> contentPaneItemRemovedEvent;
	
	public void handleContentPaneItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent ContentPaneItem contentPaneItem){
		Tab tab = contentPaneItem.getTab();
		if(tab==null) return;
		TabPane contentPane = mainView.getContentPane();
		ObservableList<Tab> tabs = contentPane.getTabs();
		for (Tab n : tabs) {
			if(n.equals(tab)) return;
		}
		if(contentPaneItem.getIndex()!=null){
			tabs.add(contentPaneItem.getIndex(), tab);
		} else {
			tabs.add(tab);
		}
		contentPaneItemAddedEvent.fire(new ContentPaneItem(tab).setIndex(tabs.indexOf(tab)));
	}

	public void handleContentPaneItemRemoveEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeRemoveEvent ContentPaneItem contentPaneItem){
		Tab tab = contentPaneItem.getTab();
		if(tab==null) return;
		TabPane contentPane = mainView.getContentPane();
		ObservableList<Tab> tabs = contentPane.getTabs();
		int index = tabs.indexOf(tab);
		if(tabs.remove(tab)){
			contentPaneItemRemovedEvent.fire(new ContentPaneItem(tab).setIndex(index));
		}
	}
}
