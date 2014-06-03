package org.adorsys.plh.pkix.core.client;

import javafx.scene.control.MenuBar;
import javafx.scene.control.TabPane;
import javafx.scene.control.ToolBar;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import javax.annotation.PostConstruct;
import javax.inject.Singleton;

@Singleton
public class MainView {

	private BorderPane rootNode;

	private TabPane contentBrowser;
	
	private TabPane contentPane;
	
	private TabPane fileBrowser;
	
	private HBox statusBar;
	
	private MenuBar menuBar;
	private ToolBar toolBar;
	
	@PostConstruct
	public void postConstruct(){
		rootNode = new BorderPane();

		VBox toolBarArea = new VBox();
		menuBar = new MenuBar();
		toolBarArea.getChildren().add(menuBar);
		toolBar = new ToolBar();
		toolBarArea.getChildren().add(toolBar);
		rootNode.setTop(toolBarArea);

		statusBar = new HBox();
		rootNode.setBottom(statusBar);

		contentBrowser = new TabPane();
		rootNode.setLeft(contentBrowser);
		
		fileBrowser = new TabPane();
		rootNode.setRight(fileBrowser);
		
		contentPane = new TabPane();
		rootNode.setCenter(contentPane);
	}
	
	public BorderPane getRootNode() {
		return rootNode;
	}

	public TabPane getContentBrowser() {
		return contentBrowser;
	}

	public TabPane getContentPane() {
		return contentPane;
	}

	public TabPane getFileBrowser() {
		return fileBrowser;
	}

	public HBox getStatusBar() {
		return statusBar;
	}

	public MenuBar getMenuBar() {
		return menuBar;
	}

	public ToolBar getToolBar() {
		return toolBar;
	}
	
}
