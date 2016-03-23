package org.coniks.coniks_server;

import utils.ServerUtils;

public class SubtreeNode extends TreeNode {

    public byte[] prefix;

    public SubtreeNode (byte[] prefix) {
	left = null; // the left child of the node
	right = null; // the right child of the node 
	level = -1; // indicates the level in the tree
	
	name = null; // used for debugging

	this.prefix = prefix;
    }

    public TreeNode clone(TreeNode parent, long ep0, long ep1){
	SubtreeNode cloneN = new SubtreeNode(this.prefix);
	cloneN.parent = parent;

	String prefixStr = ServerUtils.bytesToHex(prefix);
	SubtreeSerialization.cloneSerializedTree(ep0, ep1, prefixStr);

	return cloneN;
    }

} // ends SubtreeNode
