package de.hub.se.jqf.cluster.tracing;

import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;

/**
 * Entry point for fuzzing while saving execution traces.
 *
 * @author lam
 */
public class TraceSavingDriver {

    public static void main(String[] args) {
        if (args.length < 2){
            System.err.println("Usage: java " + TraceSavingDriver.class + " TEST_CLASS TEST_METHOD [OUTPUT_DIR [SEEDS...]]");
            System.exit(1);
        }

        String testClassName  = args[0];
        String testMethodName = args[1];
        String outputDirectoryName = args.length > 2 ? args[2] : "fuzz-results";
        File outputDirectory = new File(outputDirectoryName);
        File[] seedFiles = null;
        if (args.length > 3) {
            seedFiles = new File[args.length-3];
            for (int i = 3; i < args.length; i++) {
                seedFiles[i-3] = new File(args[i]);
            }
        }

        try {
            // Load the guidance
            String title = testClassName+"#"+testMethodName;
            ZestGuidance guidance = seedFiles != null ?
                    new TraceSavingGuidance(title, null, outputDirectory, seedFiles) :
                    new TraceSavingGuidance(title, null, outputDirectory, new File[]{});

            // Ensure that generators are being traced
            System.setProperty("jqf.traceGenerators", "true");

            // Run the Junit test
            GuidedFuzzing.run(testClassName, testMethodName, guidance, System.out);
            if (Boolean.getBoolean("jqf.logCoverage")) {
                System.out.println(String.format("Covered %d edges.",
                        guidance.getTotalCoverage().getNonZeroCount()));
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }

    }
}

