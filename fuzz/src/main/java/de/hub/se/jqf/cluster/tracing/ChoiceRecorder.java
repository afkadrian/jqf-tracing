package de.hub.se.jqf.cluster.tracing;

import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.instrument.tracing.events.BranchEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.CallEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.ReturnEvent;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEventVisitor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ChoiceRecorder implements TraceEventVisitor {
    private ArrayList<String> randomChoices;
    private ArrayList<Integer> currentChoices;
    private boolean generatorEntered;
    private Pattern choiceMethodPattern;

    public ChoiceRecorder() {
        randomChoices = new ArrayList<String>();
        currentChoices = new ArrayList<Integer>();

        // TODO: Should we also match parameter values, e.g., nextInt(int,int)
        choiceMethodPattern = Pattern.compile("Generator#(?<methodName>[a-zA-Z]+)\\("); // attempt to retrieve the method identifier
    }

    public List<String> getRandomChoiceSequence() {
        return randomChoices;
    }

    @Override
    public void visitCallEvent(CallEvent c) {

        // Ensure we only record choices within the "generate" method of the generator
        if (!generatorEntered) {
            if (c.getInvokedMethodName().contains("Generator#generate")) {
                generatorEntered = true;
            }

            if (!generatorEntered) {
                return;
            }
        }

        // Now we can attempt to identify the called random choice method
        // E.g.: CalendarGenerator#nextInt(Lcom/pholser/junit/quickcheck/random/SourceOfRandomness;I)I
        String m = c.getInvokedMethodName(); // The complete method description
        Matcher choiceMethodMatcher = choiceMethodPattern.matcher(m);
        if (choiceMethodMatcher.find()) {
            String invokedMethod = choiceMethodMatcher.group("methodName");

            switch (invokedMethod) {
                case "nextInt":
                    randomChoices.add("INT");
                    break;
                case "nextDouble":
                    randomChoices.add("DOUBLE");
                    break;
                case "nextBoolean":
                    randomChoices.add("BOOLEAN");
                    break;
                case "nextChar":
                    randomChoices.add("CHAR");
                    break;
                case "choose":
                    randomChoices.add("CHOOSE");
                    break;
                default:
                    break;
            }
        }
    }

    public void stopRecording() {
        generatorEntered = false;
    }

    @Override
    public void visitReturnEvent(ReturnEvent r) {
        return;
    }

    @Override
    public void visitBranchEvent(BranchEvent e) {
        return;
    }

}
