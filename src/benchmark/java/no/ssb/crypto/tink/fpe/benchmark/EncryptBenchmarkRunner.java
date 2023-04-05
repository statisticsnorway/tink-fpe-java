package no.ssb.crypto.tink.fpe.benchmark;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public class EncryptBenchmarkRunner
{
    public static void main(String[] args) throws Exception {
        Options opt  = new OptionsBuilder()
                .include(EncryptBenchmark.class.getSimpleName())
                .forks(1)
                .build();
        new Runner(opt).run();
    }
}
