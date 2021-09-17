package de.hub.se.jqf.cluster.tracing;


import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


public class ChoiceSequenceTree {

    protected Node root;

    protected int uniquePaths;

    protected ArrayList<Node> allNodes;

    public ChoiceSequenceTree() {

        this.root = new Node("ROOT", 0, 0);
        this.allNodes = new ArrayList<Node>();
        this.allNodes.add(this.root);
        this.uniquePaths = 0;
    }


    /** Inserting a choice sequence into the tree.
     * @param choiceSequence
     * @return
     */
    public void insert(ArrayList<String> choiceSequence) {

        Node node = this.root;

        for (int i = 0; i < choiceSequence.size(); i++) {

            String choiceType = choiceSequence.get(i);

            Node child = node.children.get(choiceType);

            if (child == null) {
                child = node.setChild(choiceType, i);
            }
            //checking if we are on the right track.
            if (!child.type.equals(choiceType)) {
                System.out.println("ERROR: BUILDING TREE FAILED!!");
            }
            node = child;
        }
        if (!node.is_end_of_choice_sequence) {
            node.is_end_of_choice_sequence = true;
            uniquePaths++;
        }
    }

    public String[][] adjMatrix() {

        String[][] matrix = new String[allNodes.size()][allNodes.size()];

        for (int i = 0; i < allNodes.size(); i++) {

            Node node = allNodes.get(i);
            for (String type : node.children.keySet()) {

                matrix[i][node.children.get(type).ID] = type;
            }
        }
        return matrix;
    }

    public void save(File outputDirectory) {

        String csv = "Node,0,1,2,3,4\n";

        for (Node node : allNodes) {

            String line = node.type;
            int j = 0;
            for (String type : node.children.keySet()) {
                line = line + "," + node.children.get(type).ID;
                j++;
            }
            while (j<5) {
                line = line + "," + ".";
                j++;
            }
            csv = csv + line + "\n";
        }

        File adj = new File(outputDirectory, "adjList.csv");
        try (PrintWriter out = new PrintWriter(adj)) {
            out.println(csv);
        }
        catch (FileNotFoundException e) {
            System.out.println("Saving adjacency list failed!");
        }

    }

    public String print(){

        String list = "";

        for (int i = 0; i < allNodes.size(); i++) {
            Node node = allNodes.get(i);
            list = list + node.type + "\t:";
            for (String type : node.children.keySet()) {
                list = list + type + "." + node.children.get(type).ID + "\t";

            }
            list = list + "\n";
        }

        //System.out.println(list);
        return list;

    }

    public int getUniquePaths() {
        return uniquePaths;
    }

    public int getNumLeafs() {
        int i = 0;
        for (Node node : allNodes) {
            if (node.is_end_of_choice_sequence && node.deg()==0) {
                i++;
            }
        }
        return i;
    }

    public int size() {
        return allNodes.size();
    }

    public ArrayList<Node> getAllNodes() {
        return allNodes;
    }

    public double branchDegree() {

        int i = 0;
        double deg = 0;
        for (Node node : allNodes) {
            if (node.deg() > 1) {
                i++;
                deg = deg + node.deg();
            }

        }

        if (i>0) return deg/i;
        else return 0;
    }



    public class Node {

        protected int ID;
        protected int depth;
        protected String type;
        protected Map<String, Node> children;
        protected Node parent;
        protected boolean is_end_of_choice_sequence;

        protected Node(String type, int ID, int depth) {

            this.ID = ID;
            this.depth = depth;
            this.type = type;
            this.children = new HashMap<String, Node>();
            this.parent = null;
            this.is_end_of_choice_sequence = false;

        }
        protected Node(String type, int ID, int depth, Node parent) {
            this(type, ID, depth);
            this.parent = parent;
        }

        /** This method returns the child node of the given type.
         *
         * ONLY CALL IF CHILD OF TYPE DOESNT EXIST!!!
         *
         * @param type - the choice type
         * @return Childnode node of the given type.
         */
        protected Node setChild(String type, int depth) {

            Node node = new Node(type, allNodes.size(), depth,this);
            this.children.put(type, node);
            allNodes.add(node);
            return node;

        }

        protected ArrayList<String> getChildren() {

            ArrayList<String> children = new ArrayList<String>();
            for (int i = 0; i < this.children.size(); i++) {
                children.add(this.children.get(i).type);
            }
            return children;
        }

        protected int deg() {

            return this.children.keySet().size();
        }

        public Node getParent() {

            if (this.type.equals("ROOT")) {
                return this;
            }
            else return this.parent;
        }
    }

}