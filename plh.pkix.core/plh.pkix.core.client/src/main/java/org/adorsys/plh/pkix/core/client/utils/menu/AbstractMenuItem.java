package org.adorsys.plh.pkix.core.client.utils.menu;

import javafx.scene.control.MenuItem;

public abstract class AbstractMenuItem {
	
	private final MenuItem menuItem;
	
	private Integer index;

	public AbstractMenuItem(MenuItem menuItem) {
		this.menuItem = menuItem;
	}

	public MenuItem getMenuItem() {
		return menuItem;
	}
	
	public Integer getIndex() {
		return index;
	}

	public void setIndex(Integer index) {
		this.index = index;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((menuItem == null) ? 0 : menuItem.hashCode());
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
		AbstractMenuItem other = (AbstractMenuItem) obj;
		if (menuItem == null) {
			if (other.menuItem != null)
				return false;
		} else if (!menuItem.equals(other.menuItem))
			return false;
		return true;
	}
}
