package org.coniks.merkletree;

/** Defines the behavior of a TreeNode used in a MerkleTree.
 */
public interface MerkleNode {

    public MerkleNode clone(InteriorNode parent);
    public byte[] hash(MerkleTree tree);
    public boolean isEmpty();

}
