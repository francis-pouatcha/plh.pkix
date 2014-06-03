package org.adorsys.plh.pkix.core.client.toolbar;

import javafx.collections.ObservableList;
import javafx.scene.Node;
import javafx.scene.control.ToolBar;

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
public class ToolBarController {

	@Inject
	private MainView mainView;
	
	@Inject
	@NodeAddedEvent
	private Event<ToolBarItem> toolBarItemAddedEvent;
	
	@Inject
	@NodeRemovedEvent
	private Event<ToolBarItem> toolBarItemRemovedEvent;
	
	public void handleToolBarItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent ToolBarItem toolBarItem){
		Node node = toolBarItem.getNode();
		if(node==null) return;
		ToolBar toolBar = mainView.getToolBar();
		ObservableList<Node> items = toolBar.getItems();
		for (Node n : items) {
			if(n.equals(node)) return;
		}
		if(toolBarItem.getIndex()!=null){
			items.add(toolBarItem.getIndex(), node);
		} else {
			items.add(node);
		}
		toolBarItemAddedEvent.fire(new ToolBarItem(node).setIndex(items.indexOf(node)));
	}

	public void handleToolBarItemRemoveEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeRemoveEvent ToolBarItem toolBarItem){
		Node node = toolBarItem.getNode();
		if(node==null) return;
		ToolBar toolBar = mainView.getToolBar();
		ObservableList<Node> items = toolBar.getItems();
		int index = items.indexOf(node);
		if(items.remove(node)){
			toolBarItemRemovedEvent.fire(new ToolBarItem(node).setIndex(index));
		}
	}
}
