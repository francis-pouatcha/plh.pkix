package org.adorsys.plh.pkix.core.client.statusbar;

import javafx.collections.ObservableList;
import javafx.scene.Node;
import javafx.scene.layout.HBox;

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
public class StatusBarController {

	@Inject
	private MainView mainView;
	
	@Inject
	@NodeAddedEvent
	private Event<StatusBarItem> statusBarItemAddedEvent;
	
	@Inject
	@NodeRemovedEvent
	private Event<StatusBarItem> statusBarItemRemovedEvent;
	
	public void handleToolBarItemAddEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeAddEvent StatusBarItem statusBarItem){
		Node node = statusBarItem.getNode();
		if(node==null) return;
		HBox statusBar = mainView.getStatusBar();
		ObservableList<Node> children = statusBar.getChildren();
		for (Node n : children) {
			if(n.equals(node)) return;
		}
		if(statusBarItem.getIndex()!=null){
			children.add(statusBarItem.getIndex(), node);
		} else {
			children.add(node);
		}
		statusBarItemAddedEvent.fire(new StatusBarItem(node).setIndex(children.indexOf(node)));
	}

	public void handleToolBarItemRemoveEvent(@Observes(notifyObserver=Reception.ALWAYS) @NodeRemoveEvent StatusBarItem statusBarItem){
		Node node = statusBarItem.getNode();
		if(node==null) return;
		HBox statusBar = mainView.getStatusBar();
		ObservableList<Node> children = statusBar.getChildren();
		int index = children.indexOf(node);
		if(children.remove(node)){
			statusBarItemRemovedEvent.fire(new StatusBarItem(node).setIndex(index));
		}
	}
}
