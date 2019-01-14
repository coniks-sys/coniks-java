package org.coniks.merkletree;

import java.nio.ByteBuffer;

// coniks-java imports
import org.coniks.crypto.Digest;

/** Represents an interior node in the CONIKS binary Merkle
 * prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */

public class EmptyNode extends TreeNode implements MerkleNode {

    public static final String EMPTY_IDENTIFIER = "E";

    private byte[] index;

    public EmptyNode(MerkleNode p, int lvl) {
        super(p, lvl);
        index = null;
    }

    public byte[] getIndex() {
        return index;
    }

    public MerkleNode clone(InteriorNode parent) {
        EmptyNode cloneN = new EmptyNode(parent, this.level);

        // FIXME: this needs to do a fully copy of the index array
        cloneN.index = this.index;
    }

    public byte[] hash(MerkleTree tree) {
        byte[] emptyId = Convert.strToBytes(EMPTY_IDENTIFIER);
        byte[] lvlBytes = Convert.intToBytes(this.level);

        byte[] emptyBytes = new byte[this.emptyId.length+
                                    tree.getNonce().length+
                                    this.index.length+
                                    lvlBytes.length];

        ByteBuffer arr = ByteBuffer.wrap(emptyBytes);
        arr.put(emptyId);
        arr.put(tree.getNonce());
        arr.put(this.index);
        arr.put(lvlBytes);

        return Digest.digest(arr.array());
    }

    public boolean isEmpty() {
        return true;
    }

}
