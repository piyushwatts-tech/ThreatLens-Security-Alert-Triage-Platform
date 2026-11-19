package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** PowerShell launched with obfuscation / download-cradle indicators; extra risk when spawned by Office. */
@Component
public class SuspiciousPowerShellRule implements DetectionRule {

    private static final Pattern PS = Pattern.compile("(?i)(powershell|pwsh)(\\.exe)?$");
    private static final Map<String, Pattern> INDICATORS = new LinkedHashMap<>();
    static {
        INDICATORS.put("encodedCommand", Pattern.compile("(?i)\\s-(e|en|enc|enco|encodedcommand)\\s+[A-Za-z0-9+/=]{16,}"));
        INDICATORS.put("hiddenWindow", Pattern.compile("(?i)\\s-w(indowstyle)?\\s+h(idden)?"));
        INDICATORS.put("noProfile", Pattern.compile("(?i)\\s-nop(rofile)?\\b"));
        INDICATORS.put("executionPolicyBypass", Pattern.compile("(?i)-ex(ecutionpolicy)?\\s+bypass"));
        INDICATORS.put("downloadCradle", Pattern.compile("(?i)(downloadstring|downloadfile|invoke-webrequest|iwr |net\\.webclient|start-bitstransfer)"));
        INDICATORS.put("invokeExpression", Pattern.compile("(?i)\\b(iex|invoke-expression)\\b"));
    }
    private static final Pattern ENCODED = Pattern.compile("(?i)\\s-(?:e|en|enc|enco|encodedcommand)\\s+([A-Za-z0-9+/=]{16,})");
    private static final Set<String> OFFICE = Set.of("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe", "wscript.exe");

    public String id() { return "WIN-004"; }
    public String name() { return "Suspicious PowerShell execution"; }
    public String description() { return "PowerShell started with encoded commands, hidden window or download cradle."; }
    public MitreTechnique technique() { return MitreTechnique.POWERSHELL; }
    public int baseScore() { return 50; }
    public Set<EventType> eventTypes() { return Set.of(EventType.PROCESS_CREATE); }
    public String logic() { return "EventID 4688/Sysmon 1 where Image ~ powershell and CommandLine has >= 2 obfuscation/download indicators"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        for (SecurityEvent e : events) {
            if (e.getProcess() == null || !PS.matcher(e.getProcess()).find() || e.getCommandLine() == null) continue;
            String cmd = " " + e.getCommandLine();
            List<String> hits = INDICATORS.entrySet().stream()
                    .filter(en -> en.getValue().matcher(cmd).find()).map(Map.Entry::getKey).toList();
            String decoded = decode(cmd);
            if (decoded != null) {
                for (String k : List.of("downloadCradle", "invokeExpression")) {
                    if (!hits.contains(k) && INDICATORS.get(k).matcher(decoded).find()) {
                        hits = new ArrayList<>(hits);
                        hits.add(k + "(decoded)");
                    }
                }
            }
            if (hits.size() < 2) continue;
            String parent = e.getParentProcess() == null ? "" : e.getParentProcess();
            String parentExe = parent.substring(parent.lastIndexOf('\\') + 1).toLowerCase(Locale.ROOT);
            boolean office = OFFICE.contains(parentExe);
            Detection.Builder b = Detection.builder(this)
                    .title("Suspicious PowerShell on " + e.getHost() + (office ? " spawned by " + parentExe : ""))
                    .description("User " + e.getUsername() + " ran PowerShell with " + String.join(", ", hits)
                            + (office ? ". Parent is " + parentExe + ", consistent with a malicious document (T1566.001)." : "."))
                    .groupKey(e.getHost() + "/" + Integer.toHexString(cmd.hashCode()))
                    .host(e.getHost()).username(e.getUsername())
                    .events(List.of(e))
                    .evidence("indicators", hits)
                    .evidence("parentProcess", parent)
                    .evidence("commandLine", e.getCommandLine().length() > 500 ? e.getCommandLine().substring(0, 500) + "…" : e.getCommandLine())
                    .factor("officeParent", office ? 20 : 0)
                    .factor("indicatorCount", Math.min(10, (hits.size() - 2) * 4));
            if (decoded != null) b.evidence("decodedCommand", decoded);
            out.add(b.build());
        }
        return out;
    }

    static String decode(String cmd) {
        Matcher m = ENCODED.matcher(cmd);
        if (!m.find()) return null;
        try {
            return new String(Base64.getDecoder().decode(m.group(1)), StandardCharsets.UTF_16LE);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
