package de.hub.se.jqf.cluster.tracing;

import com.pholser.junit.quickcheck.internal.Ranges;
import edu.berkeley.cs.jqf.fuzz.guidance.StreamBackedRandom;
import edu.berkeley.cs.jqf.fuzz.junit.quickcheck.FastSourceOfRandomness;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

public class TracingSourceOfRandomness extends FastSourceOfRandomness {
    private ArrayList<String> choiceTypes;

    // TODO: Wrap choices into Object or some other data structure
    private ArrayList<Integer> choiceValues;

    public TracingSourceOfRandomness(StreamBackedRandom delegate) {
        super(delegate);
        this.choiceTypes = new ArrayList<String>();
        this.choiceValues = new ArrayList<Integer>();
    }

    public ArrayList<String> getChoiceTypes() {
        return choiceTypes;
    }

    public ArrayList<Integer> getChoiceValues() {
        return choiceValues;
    }

    @Override
    public byte nextByte(byte min, byte max) {
        byte choice = super.nextByte(min, max);
        choiceTypes.add("BYTE");
        choiceValues.add((int) choice);
        return choice;
    }

    @Override
    public short nextShort(short min, short max) {
        short choice = super.nextShort(min, max);
        choiceTypes.add("SHORT");
        choiceValues.add((int) choice);
        return choice;
    }

    @Override
    public char nextChar(char min, char max) {
        char choice = super.nextChar(min, max);
        choiceTypes.add("CHAR");
        choiceValues.add((int) choice);
        return choice;
    }

    @Override
    public int nextInt() {
        int choice = super.nextInt();
        choiceTypes.add("INT");
        choiceValues.add(choice);
        return choice;
    }

    @Override
    public int nextInt(int n) {
        int choice = super.nextInt(n);
        choiceTypes.add("INT");
        choiceValues.add(choice);
        return choice;
    }

    @Override
    public int nextInt(int min, int max) {
        int choice = super.nextInt(min, max);
        choiceTypes.add("INT");
        choiceValues.add(choice);
        return choice;
    }

    @Override
    public boolean nextBoolean() {
        boolean choice = super.nextBoolean();
        choiceTypes.add("BOOL");
        choiceValues.add(choice ? 1:0);
        return choice;
    }

    @Override
    public long nextLong(long min, long max) {
        long choice = super.nextLong(min, max);
        choiceTypes.add("LONG");
        System.out.println("WARNING: Downcasting long choice to integer.");
        choiceValues.add((int) choice);
        return choice;
    }

    @Override
    public <T> T choose(Collection<T> items) {
        Object[] array = items.toArray(new Object[items.size()]);
        int choice = super.nextInt(array.length);
        choiceTypes.add("CHOOSE");
        choiceValues.add(choice);
        return (T) array[choice];
    }

    @Override
    public <T> T choose(T[] items) {
        int choice = super.nextInt(items.length);
        choiceTypes.add("CHOOSE");
        choiceValues.add(choice);
        return items[choice];
    }

}
