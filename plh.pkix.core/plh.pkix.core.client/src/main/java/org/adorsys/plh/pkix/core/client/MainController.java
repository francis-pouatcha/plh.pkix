package org.adorsys.plh.pkix.core.client;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javafx.scene.Scene;
import javafx.stage.Stage;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;

@Singleton
public class MainController {

	@Inject
	private MainView mainView;

	private Stage stage;

	public void start(Stage stage, Locale locale,String... styleSheets){
		this.stage = stage;
		try {
			System.setProperty("java.awt.headless", "false");
			Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
			Scene scene = new Scene(mainView.getRootNode(), screenSize.getWidth()*0.95, screenSize.getHeight()*0.9);
			List<String> styles = Arrays.asList(styleSheets);
			for (String styleSheet : styles) {
				scene.getStylesheets().add(styleSheet);
			}
			stage.setScene(scene);
			stage.setTitle("ADPHARMA FX 2.0");
			stage.show();
		} catch (Exception e){
			throw e;
		}
	}

	@PostConstruct
	public void postConstruct(){
//		new Timer(new Runnable() {
//			@Override
//			public void run() {
//				mainView.getTimeLabel().setText(new SimpleDateFormat("HH:mm:ss").format(new Date()));
//
//			}
//		}).start();
	}
}
