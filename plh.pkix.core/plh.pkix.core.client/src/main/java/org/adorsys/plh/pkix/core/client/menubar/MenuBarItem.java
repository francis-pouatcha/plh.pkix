package org.adorsys.plh.pkix.core.client.menubar;

import javafx.scene.control.Menu;

public class MenuBarItem {
	private final Menu menu;
	private Integer index;

	public MenuBarItem(Menu menu) {
		this.menu = menu;
	}

	public Menu getMenu() {
		return menu;
	}

	public Integer getIndex() {
		return index;
	}

	public MenuBarItem setIndex(Integer index) {
		this.index = index;
		return this;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((menu == null) ? 0 : menu.hashCode());
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
		MenuBarItem other = (MenuBarItem) obj;
		if (menu == null) {
			if (other.menu != null)
				return false;
		} else if (!menu.equals(other.menu))
			return false;
		return true;
	}
	
}
