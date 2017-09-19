package org.coniks.merkletree;

/** Defines the behavior of a TreeNode used in a MerkleTree.
 */
public interface MerkleNode {

    public TreeNode clone(TreeNode parent);
    public byte[] serialize(MerkleTree tree);
    public byte[] hash(MerkleTree tree);

}
