package kernel.track.repositories;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.errors.IncorrectObjectTypeException;
import org.eclipse.jgit.errors.MissingObjectException;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import kernel.track.models.KernelCVE;
import kernel.track.models.KernelVersion;

public class KernelCVERepository {
    private static final Logger logger = LogManager.getLogger(KernelCVERepository.class);

    private final Map<String, KernelCVE> kernelCVEs;
    private final Map<String, Map<String, Map<String, Map<String, String>>>> streamData;
    private final Map<String, Map<String, Map<String, String>>> streamFixes;

    public KernelCVERepository(Path linuxKernelCVEsData) throws StreamReadException, DatabindException, IOException {
        final ObjectMapper mapper = new ObjectMapper();

        Path kernelCvesJson = linuxKernelCVEsData.resolve("./kernel_cves.json");
        kernelCVEs = mapper.readValue(Files.readAllBytes(kernelCvesJson),
            new TypeReference<Map<String, KernelCVE>>() {});
        kernelCVEs.forEach((cveid, cve)->{
            cve.setId(cveid);
        });

        Path streamDataJson = linuxKernelCVEsData.resolve("./stream_data.json");
        streamData = mapper.readValue(Files.readAllBytes(streamDataJson),
            new TypeReference<Map<String, Map<String, Map<String, Map<String, String>>>>>() {});

        Path streamFixesJson = linuxKernelCVEsData.resolve("./stream_fixes.json");
        streamFixes = mapper.readValue(Files.readAllBytes(streamFixesJson),
            new TypeReference<Map<String, Map<String, Map<String, String>>>>() {});
    }

    private Set<String> selectFromStreamDataCond(KernelVersion version, BiPredicate<KernelVersion,KernelVersion> predicate) {
        Set<String> result = new HashSet<>();
        Map<String, Map<String, Map<String, String>>> substreams = streamData.get(version.STREAM_VERSION);
        if (substreams == null) return result;
        substreams.entrySet().forEach((entry)->{
            KernelVersion substream = new KernelVersion(entry.getKey());
            if (predicate.test(version, substream))
                result.addAll(entry.getValue().keySet());
        });
        return result;
    }

    public Set<String> selectFromStreamDataNotGreaterThan(KernelVersion version) {
        return selectFromStreamDataCond(version, (v, o)->(v.compareTo(o) <= 0));
    }

    public Set<String> selectFromStreamDataGreaterThan(KernelVersion version) {
        return selectFromStreamDataCond(version, (v, o)->(v.compareTo(o) > 0));
    }

    public void retainIf(Set<String> selectedIds, Predicate<KernelCVE> predicate) {
        selectedIds.removeIf((id)->!predicate.test(kernelCVEs.get(id)));
    }

    public Set<String> whereFixed(Set<String> selectedIds, KernelVersion version, Git git) {
        Set<String> filtered = new HashSet<String>();
        selectedIds.removeIf((id)->{
            Map<String, Map<String, String>> streams = streamFixes.get(id);
            if (streams == null) return false;
            Map<String, String> stream = streams.get(version.STREAM_VERSION);
            if (stream == null) return false;
            String fixCommit = stream.get("cmd_id");
            if (fixCommit == null) return false;
            ObjectId fixCommitObject = ObjectId.fromString(fixCommit);
            try (RevWalk walk = new RevWalk(git.getRepository())) {
                RevCommit fixCommitRef = walk.parseCommit(fixCommitObject);
                if (fixCommitRef != null) {
                    filtered.add(id);
                    return true;
                }
            } catch (MissingObjectException moe) {
                logger.error(String.format("[%s]: supplied commit %s does not exist", id, fixCommit), moe);
            } catch (IncorrectObjectTypeException iote) {
                logger.error(String.format("[%s]: supplied id %s is not a commit or annotated tag", id, fixCommit), iote);
            } catch (IOException ioe) {
                logger.error(String.format("[%s]: io error occured while parsing commit %s", id, fixCommit), ioe);
            }
            return false;
        });
        return filtered;
    }

    public KernelCVE selectById(String cveId) {
        return kernelCVEs.get(cveId);
    }
}
