package org.coniks.coniks_server;

import org.coniks.crypto.Keys;
import java.util.PriorityQueue;
import java.security.interfaces.DSAPublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import org.javatuples.Triplet;

public class UpdateHistoryTiming{

        public static void main(String[] args){

                int numUsers = 0;
                try{
                        numUsers = Integer.parseInt(args[0]);
                }
                catch(NumberFormatException e){
                        System.err.println("Wrong format - numUsers");
                        return;
                }

                int numTrials = 0;
                try{
                        numTrials = Integer.parseInt(args[1]);
                }
                catch(NumberFormatException e){
                        System.err.println("Wrong format - numTrials");
                        return;
                }

                int numInserts = 0;
                try{
                        numInserts = Integer.parseInt(args[2]);
                }
                catch(NumberFormatException e){
                        System.err.println("Wrong format - numInserts");
                        return;
                }

                // generate the key pair --> used for all fake users
                // since we don't want to get caught up timing
                // key generation, too
                KeyPair kp = null;
                try {
                        kp = Keys.generateDSAKeyPair();
                }
                catch(NoSuchAlgorithmException e) {
                        // let's not quite bail here
                        throw new UnsupportedOperationException("DSA algorithm is null");
                }

                for(int t = 0; t < numTrials; t++){

                        // initialize the directory
                        PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQueue =
                                new PriorityQueue<Triplet<byte[], UserLeafNode, Operation>>(
                                                                                            16384, new ServerUtils.PrefixComparator());

                        RootNode initRoot = TreeBuilder.copyExtendTree(null, pendingQueue);

                        // generate each fake user
                        for(int i = 0; i < numUsers; i++){
                                String uname = i+"";
                                String pk = uname+" PK";
                                byte[] index = ServerUtils.unameToIndex(uname);
                                UserLeafNode uln = new UserLeafNode(uname, pk, 0, 0,
                                                                    false, false, (DSAPublicKey)kp.getPublic(), index);
                                pendingQueue.add(Triplet.with(index, uln, (Operation)new Register()));
                        }

                        long setupStart = System.nanoTime();

                        RootNode root = TreeBuilder.copyExtendTree(initRoot, pendingQueue);

                        // check that we got a good tree
                        if(root == null) {
                                // let's not quite bail here
                                throw new UnsupportedOperationException("Bad tree");
                        }

                        long setupEnd = System.nanoTime();
                        long setupDur = setupEnd - setupStart;
                        //System.err.println(t+": "+setupDur+"ns");

                        pendingQueue.clear();

                        /* Benchmark starts here */

                        // now do 1K inserts and time the update
                        for (int i = 0; i < numInserts; i++){
                                String uname = (numUsers+i)+"";
                                String pk = uname+" PK";
                                byte[] index = ServerUtils.unameToIndex(uname);
                                UserLeafNode uln = new UserLeafNode(uname, pk, 0, 0,
                                                                    false, false, (DSAPublicKey)kp.getPublic(), index);
                                pendingQueue.add(Triplet.with(index, uln, (Operation)new Register()));
                        }

                        long timeUpdateStart = System.nanoTime();

                        root = TreeBuilder.copyExtendTree(root, pendingQueue);

                        // check that we got a good tree
                        if(root == null) {
                                // let's not quite bail here
                                throw new UnsupportedOperationException("Bad tree");
                        }

                        long timeComputeDone = System.nanoTime();
                        long timeToCompute = timeComputeDone - timeUpdateStart;

                        System.out.println(numUsers+", "+timeToCompute);
                }

        }
}
