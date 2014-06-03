package org.adorsys.plh.pkix.core.client.statusbar;

import javafx.scene.Node;

public class StatusBarItem {
	private final Node node;
	private Integer index;

	public StatusBarItem(Node node) {
		this.node = node;
	}

	public Node getNode() {
		return node;
	}

	public Integer getIndex() {
		return index;
	}

	public StatusBarItem setIndex(Integer index) {
		this.index = index;
		return this;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((node == null) ? 0 : node.hashCode());
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
		StatusBarItem other = (StatusBarItem) obj;
		if (node == null) {
			if (other.node != null)
				return false;
		} else if (!node.equals(other.node))
			return false;
		return true;
	}
	
}
