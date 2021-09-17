
package de.hub.se.jqf.cluster.tracing;

import edu.berkeley.cs.jqf.fuzz.ei.ExecutionIndexingGuidance;
import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.util.IOUtils;
import edu.berkeley.cs.jqf.instrument.tracing.SingleSnoop;
import edu.berkeley.cs.jqf.instrument.tracing.events.CallEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * A guidance that saves execution traces.
 * Based on implementation of {@link ExecutionIndexingGuidance}.
 * @author lam
 */
public class TraceSavingGuidance extends ZestGuidance {

    /** The execution indexing logic. */
    //protected ExecutionIndexingState eiState;

    /** The choice types of the current input */
    protected ArrayList<String> currentChoiceTypes;

    /** The choice values of the current input */
    protected ArrayList<Integer> currentChoiceValues;

    /** The mapping between choice type sequences and output file */
    protected HashMap<String, File> csFiles;

    /** The choice type sequence ids */
    protected int nextChoiceSequenceId = 0;

    /** The entry point to the test method we are fuzzing. */
    protected String entryPoint;

    /** Whether the entry point has been encountered in the current run */
    protected boolean testEntered;

    /** The last event handled by this guidance */
    protected TraceEvent lastEvent;

    /** Whether to only save traces for executions that increased coverage */
    protected final boolean LOG_INCREASING_COV_ONLY = Boolean.getBoolean("jqf.cluster.LOG_INCREASING_COV_ONLY");

    /** Whether to save traces for executions where no method was covered **/
    protected final boolean LOG_EMPTY_METHOD_COV = Boolean.getBoolean("jqf.cluster.LOG_EMPTY_METHOD_COV");

    /** The set of covered methods **/
    protected Set<Integer> coveredMethods = new HashSet<Integer>();

    /** The output directory **/
    protected File outputDirectory;

    /** The file where all choice sequences are written. **/
    protected File choiceSequenceFile;

    /** The file where all coverage data is written. */
    protected File coverageFile;

    /** The file where method coverage data is written. */
    protected File methodCoverageFile;

    /** The map from method names to ids **/
    protected Map<String, Integer> methodNameToId = new HashMap<String, Integer>();

    /** The method id counter **/
    protected int nextMethodId = 0;

    /** The file where instruction id to method name mapping data is written. */
    protected File idToMethodNameFile;

    /** The choice sequence tree. */
    protected ChoiceSequenceTree choiceSequenceTree;

    /** The file where the data of the choice sequence tree size is written. */
    protected File csTreeFile;
    protected Date lastEntry;

    /**
     * Constructs a new guidance instance.
     *
     * @param testName the name of test to display on the status screen
     * @param duration the amount of time to run fuzzing for, where
     *                 {@code null} indicates unlimited time.
     * @param outputDirectory the directory where fuzzing results will be written
     * @throws IOException if the output directory could not be prepared
     */
    public TraceSavingGuidance(String testName, Duration duration, File outputDirectory) throws IOException {
        super(testName, duration, outputDirectory);
        this.outputDirectory = outputDirectory;
        this.choiceSequenceFile = new File(outputDirectory, "choice_sequences.csv");
        this.coverageFile = new File(outputDirectory, "coverage.csv");
        this.methodCoverageFile = new File(outputDirectory, "method_coverage.csv");
        this.idToMethodNameFile = new File(outputDirectory, "iid_to_method_name.csv");
        this.csFiles = new HashMap<String, File>();

        this.choiceSequenceTree = new ChoiceSequenceTree();
        this.csTreeFile = new File(outputDirectory, "cstree_data.csv");
        this.lastEntry = new Date();
        appendLineToFile(csTreeFile, "timestemp,BranchDegree,UniquePaths,NumLeafs,NumNodes");

    }

    /**
     * Constructs a new guidance instance.
     *
     * @param testName the name of test to display on the status screen
     * @param duration the amount of time to run fuzzing for, where
     *                 {@code null} indicates unlimited time.
     * @param outputDirectory the directory where fuzzing results will be written
     * @param seedInputFiles one or more input files to be used as initial inputs
     * @throws IOException if the output directory could not be prepared
     */
    public TraceSavingGuidance(String testName, Duration duration, File outputDirectory, File[] seedInputFiles)
            throws IOException {
        super(testName, duration, outputDirectory, seedInputFiles);
        this.outputDirectory = outputDirectory;
        this.choiceSequenceFile = new File(outputDirectory, "choice_sequences.csv");
        this.coverageFile = new File(outputDirectory, "coverage.csv");
        this.methodCoverageFile = new File(outputDirectory, "method_coverage.csv");
        this.idToMethodNameFile = new File(outputDirectory, "iid_to_method_name.csv");
        this.csFiles = new HashMap<String, File>();

        this.choiceSequenceTree = new ChoiceSequenceTree();
        this.csTreeFile = new File(outputDirectory, "cstree_data.csv");
        this.lastEntry = startTime;
        appendLineToFile(csTreeFile, "timestemp,BranchDegree,UniquePaths,NumLeafs,NumNodes");
    }

    /**
     * Creates a new guidance instance.
     *
     * @param testName the name of test to display on the status screen
     * @param duration the amount of time to run fuzzing for, where
     *                 {@code null} indicates unlimited time.
     * @param outputDirectory the directory where fuzzing results will be written
     * @param seedInputDir the directory containing one or more input files to be used as initial inputs
     * @throws IOException if the output directory could not be prepared
     */
    public TraceSavingGuidance(String testName, Duration duration, File outputDirectory, File seedInputDir) throws IOException {
        this(testName, duration, outputDirectory, IOUtils.resolveInputFileOrDirectory(seedInputDir));
    }

    /** Returns the banner to be displayed on the status screen */
    protected String getTitle() {
        if (blind) {
            return "Random Fuzzing (+ saving execution traces)\n" +
                    "---------------------------------------\n" +
                    //"Current unique choice sequences: " + csFiles.keySet().size() + "\n" +
                    "Current unique valid paths: " + choiceSequenceTree.getUniquePaths() + "\n" +
                    "Current number of leafs: " + choiceSequenceTree.getNumLeafs() + "\n" +
                    "Current branching degree of tree: " + choiceSequenceTree.branchDegree();
        } else {
            return  "Semantic Fuzzing with Zest (+ saving execution traces)\n" +
                    "---------------------------------------\n" +
                    //"Current unique choice sequences: " + csFiles.keySet().size() + "\n" +
                    "Current unique valid paths: " + choiceSequenceTree.getUniquePaths() + "\n" +
                    "Current number of leafs: " + choiceSequenceTree.getNumLeafs() + "\n" +
                    "Current branching degree of tree: " + choiceSequenceTree.branchDegree();

        }
    }

    @Override
    public InputStream getInput() throws GuidanceException {
        // First, reset method coverage and execution indexing state
        coveredMethods = new HashSet<Integer>();
      //  eiState = new ExecutionIndexingState();
        // Unmark "test started"
        testEntered = false;

        // Then, do the same logic as ZestGuidance (e.g, return seeds, mutated inputs, or new input)
        return super.getInput();
    }

    public void setCurrentChoiceSequences(ArrayList<String> choiceTypes, ArrayList<Integer> choiceValues) {
        this.currentChoiceTypes = choiceTypes;
        this.currentChoiceValues = choiceValues;
    }

    /*
    @Override
    protected InputStream createParameterStream() {
        return;
    }
    */

    /**
     * Handles the result of a test execution.
     *
     * This method mostly delegates to the {@link ZestGuidance}, but additionally
     * incorporates some custom logic to handle the recording of traces
     */
    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        int numSavedInputsBefore = savedInputs.size();
        int nonZeroBefore = totalCoverage.getNonZeroCount();
        super.handleResult(result, error);
        int nonZeroAfter = totalCoverage.getNonZeroCount();
        int newCoverage = nonZeroAfter - nonZeroBefore;
        // Only log coverage for inputs that increased coverage?
        /*
        if (LOG_INCREASING_COV_ONLY && savedInputs.size() <= numSavedInputsBefore) {
            return;
        }

        // Log inputs that covered no methods (i.e., were rejected before reaching the test method)?
        if (coveredMethods.size() == 0 && !LOG_EMPTY_METHOD_COV) {
            return;
        }

        // Serialize coverage data to CSV
        String methodsToCSV = coveredMethods.stream()
                .map(entry -> entry.toString())
                .collect(Collectors.joining(","));
        appendLineToFile(methodCoverageFile, result.toString() + "," + methodsToCSV);

        Collection<Integer> coveredBranches = runCoverage.getCovered(); // sort?
        String branchesToCSV = coveredBranches.stream()
                .map(entry -> entry.toString())
                .collect(Collectors.joining(","));
        appendLineToFile(coverageFile, result.toString() + "," + branchesToCSV);
        */
        /*String choiceSequenceToCSV = choiceRecorder.getRandomChoiceSequence().stream()
                .map(entry -> entry.toString())
                .collect(Collectors.joining(","));
        appendLineToFile(choiceSequenceFile, result.toString() + "," + choiceSequenceToCSV);
/*
        // Handle choice sequences
        String csKey = currentChoiceTypes.toString();
        if(!csFiles.containsKey(csKey)) {
            File csFile = new File(outputDirectory, "choice_sequence_" + (nextChoiceSequenceId++) + ".csv");
            String csTypeSequence = currentChoiceTypes.stream()
                    .map(entry -> entry.toString())
                    .collect(Collectors.joining(","));
            appendLineToFile(csFile, "VALIDITY" + "," + "COV+" + "," + csTypeSequence);
            csFiles.put(csKey, csFile);
        }
        String csValueSequence = currentChoiceValues.stream()
                .map(entry -> entry.toString())
                .collect(Collectors.joining(","));
        appendLineToFile(csFiles.get(csKey), result.ordinal() + "," + newCoverage + "," + csValueSequence);
*/
        if (result == Result.SUCCESS) {

            choiceSequenceTree.insert(currentChoiceTypes);
            Date timestemp = new Date();

            if ((timestemp.getTime() - lastEntry.getTime() >= 1000) || (lastEntry.equals(startTime))) {

                long elapsed = (timestemp.getTime()-startTime.getTime());
                appendLineToFile(csTreeFile,
                        elapsed + "," + choiceSequenceTree.branchDegree() + "," + choiceSequenceTree.getUniquePaths() + "," + choiceSequenceTree.getNumLeafs() + "," + choiceSequenceTree.size());
                lastEntry = timestemp;
            }


        }

    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        if (firstThread == null) {
            firstThread = thread;
        } else if (firstThread != thread) {
            multiThreaded = true;
        }
        entryPoint = SingleSnoop.entryPoints.get(thread).replace('.', '/');
        assert entryPoint != null : ExecutionIndexingGuidance.class + " must be able to determine an entry point";

        return this::handleEvent;
    }

    /** Handles a trace event generated during test execution */
    @Override
    protected void handleEvent(TraceEvent e) {
        // Set last event to this event
        lastEvent = e;

        // Update execution indexing logic regardless of whether we are in generator or test method

        //e.applyVisitor(eiState);

        // Do not handle code coverage unless test has been entered
        if (!testEntered) {
            // Check if this event enters the test method
            if (e instanceof CallEvent) {
                CallEvent callEvent = (CallEvent) e;
                if (callEvent.getInvokedMethodName().startsWith(entryPoint)) {
                    testEntered = true;
                }
            }

            // If test method has not yet been entered, then ignore code coverage
            if (!testEntered) {
                return;
            }
        }

        // Add called method to set of covered methods
        if (e instanceof CallEvent) {
            CallEvent callEvent = (CallEvent) e;
            int iid = e.getIid();
            String methodName = callEvent.getInvokedMethodName();
            if (!methodNameToId.containsKey(methodName)) {
                int nextId = this.nextMethodId++;
                methodNameToId.put(methodName, nextId);
                appendLineToFile(idToMethodNameFile, nextId + "," + methodName);
            }
            this.coveredMethods.add(methodNameToId.get(methodName));
        }

        // Delegate to ZestGuidance for handling code coverage
        super.handleEvent(e);
    }
}
