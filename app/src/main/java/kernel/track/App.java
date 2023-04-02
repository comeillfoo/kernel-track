/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package kernel.track;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.Git;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.opencsv.bean.StatefulBeanToCsv;
import com.opencsv.bean.StatefulBeanToCsvBuilder;
import com.opencsv.exceptions.CsvDataTypeMismatchException;
import com.opencsv.exceptions.CsvRequiredFieldEmptyException;

import kernel.track.models.CVEBean;
import kernel.track.models.KernelCVE;
import kernel.track.models.KernelVersion;
import kernel.track.repositories.KernelCVERepository;
import kernel.track.utils.StreamPair;


public class App {

    private static final Logger logger = LogManager.getLogger(App.class);

    public static void writeCsvFromBeans(Path path, List<CVEBean> beans) {
        final char separator = ';';
        try (Writer writer = new FileWriter(path.toString())) {
            StatefulBeanToCsv<CVEBean> sbc = new StatefulBeanToCsvBuilder<CVEBean>(writer)
                .withSeparator(separator)
                .build();
            writer.write(String.join(
                String.valueOf(separator),
                Stream.of(CVEBean.HEADER)
                    .map((column) -> "\"" + column + "\"")
                    .toArray(String[]::new)) + "\n");
            sbc.write(beans);
        } catch (IOException|CsvDataTypeMismatchException|CsvRequiredFieldEmptyException e) {
            e.printStackTrace();
        }
    }

    private static void usage(String[] args) {
        logger.warn("Usage: java -jar kernel_track.jar [path_to_kernel] [path_to_linuxkernelcves_data]");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            usage(args);
            return;
        }

        final Path pathToKernel = Paths.get(args[0]);
        final Path pathToLinuxKernelCVEsData = Paths.get(args[1]);

        try {
            final KernelVersion version = new KernelVersion(pathToKernel);
            final KernelCVERepository repo = new KernelCVERepository(pathToLinuxKernelCVEsData);

            // first division by version
            StreamPair sets = new StreamPair(
                repo.selectFromStreamDataNotGreaterThan(version),
                repo.selectFromStreamDataGreaterThan(version));
            System.out.println(String.format("Fixed: %d, unfixed: %d", sets.FIXED.size(), sets.UNFIXED.size()));

            // second division by severity
            repo.retainIf(sets.FIXED, KernelCVE::isHighOrCritical);
            repo.retainIf(sets.UNFIXED, KernelCVE::isHighOrCritical);
            System.out.println(String.format("Fixed: %d, unfixed: %d", sets.FIXED.size(), sets.UNFIXED.size()));

            // third division by commits
            try {
                // HttpConnectionFactory oldFactory = HttpTransport.getConnectionFactory();
                // HttpTransport.setConnectionFactory(new InsecureHttpConnectionFactory());
                // // clone repo
                // Git kernel = Git.cloneRepository()
                //     .setURI(someURL)
                //     .call();
                // HttpTransport.setConnectionFactory(oldFactory);
                Git kernel = Git.open(pathToKernel.toFile());
                sets.FIXED.addAll(repo.whereFixed(sets.UNFIXED, version, kernel));
                kernel.close();
                System.out.println(String.format("Fixed: %d, unfixed: %d", sets.FIXED.size(), sets.UNFIXED.size()));
            } catch (Exception e) {
                e.printStackTrace();
            }

            // convert to dumpable beans
            final List<CVEBean> table = Stream.concat(
                sets.FIXED
                    .stream()
                    .map(repo::selectById)
                    .map(CVEBean::fixedOf),
                sets.UNFIXED
                    .stream()
                    .map(repo::selectById)
                    .map(CVEBean::unfixedOf))
                .collect(Collectors.toList());
            writeCsvFromBeans(Paths.get("./report.csv"), table);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
