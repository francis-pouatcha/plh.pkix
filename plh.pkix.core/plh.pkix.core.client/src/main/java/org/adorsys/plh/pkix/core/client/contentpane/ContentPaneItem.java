package org.adorsys.plh.pkix.core.client.contentpane;

import javafx.scene.control.Tab;

public class ContentPaneItem {
	private final Tab tab;
	private Integer index;

	public ContentPaneItem(Tab menu) {
		this.tab = menu;
	}

	public Tab getTab() {
		return tab;
	}

	public Integer getIndex() {
		return index;
	}

	public ContentPaneItem setIndex(Integer index) {
		this.index = index;
		return this;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((tab == null) ? 0 : tab.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ContentPaneItem other = (ContentPaneItem) obj;
		if (tab == null) {
			if (other.tab != null)
				return false;
		} else if (!tab.equals(other.tab))
			return false;
		return true;
	}
	
}
