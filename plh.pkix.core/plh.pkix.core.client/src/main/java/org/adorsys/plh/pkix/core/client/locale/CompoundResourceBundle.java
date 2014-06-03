package org.adorsys.plh.pkix.core.client.locale;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;
import java.util.Vector;

public class CompoundResourceBundle extends ResourceBundle {

	private List<PropertyResourceBundle> resourceBundles = new ArrayList<PropertyResourceBundle>();

	public CompoundResourceBundle(List<PropertyResourceBundle> ps) {
		resourceBundles.addAll(ps);
	}

	@Override
	protected Object handleGetObject(String key) {
		for (PropertyResourceBundle resourceBundle : resourceBundles) {
			Object handleGetObject = resourceBundle.handleGetObject(key);
			if(handleGetObject!=null) return handleGetObject;
		}
		return null;
	}

	Vector<String> keysVector = null;
	@Override
	public Enumeration<String> getKeys() {
		if(keysVector==null) {
			keysVector = new Vector<String>();
			for (PropertyResourceBundle resourceBundle : resourceBundles) {
				Enumeration<String> keys = resourceBundle.getKeys();
				while (keys.hasMoreElements()) {
					String string = keys.nextElement();
					keysVector.add(string);
				}
			}
		}
		return keysVector.elements();
	}
	
	void add(PropertyResourceBundle propertyResourceBundle){
		resourceBundles.add(propertyResourceBundle);
	}
}
