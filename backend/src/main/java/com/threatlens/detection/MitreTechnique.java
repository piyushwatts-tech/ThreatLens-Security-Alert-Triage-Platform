package com.threatlens.detection;

/** A MITRE ATT&CK (Enterprise) technique with its primary tactic. */
public record MitreTechnique(String id, String name, String tactic) {

    public static final MitreTechnique NETWORK_SERVICE_DISCOVERY =
            new MitreTechnique("T1046", "Network Service Discovery", "Discovery");
    public static final MitreTechnique BRUTE_FORCE =
            new MitreTechnique("T1110", "Brute Force", "Credential Access");
    public static final MitreTechnique PASSWORD_GUESSING =
            new MitreTechnique("T1110.001", "Brute Force: Password Guessing", "Credential Access");
    public static final MitreTechnique PASSWORD_SPRAYING =
            new MitreTechnique("T1110.003", "Brute Force: Password Spraying", "Credential Access");
    public static final MitreTechnique VALID_ACCOUNTS =
            new MitreTechnique("T1078", "Valid Accounts", "Initial Access");
    public static final MitreTechnique NETWORK_DOS =
            new MitreTechnique("T1498", "Network Denial of Service", "Impact");
    public static final MitreTechnique POWERSHELL =
            new MitreTechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution");
    public static final MitreTechnique ACCOUNT_MANIPULATION =
            new MitreTechnique("T1098", "Account Manipulation", "Persistence");
    public static final MitreTechnique CLEAR_EVENT_LOGS =
            new MitreTechnique("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion");
    public static final MitreTechnique EXFIL_ALT_PROTOCOL =
            new MitreTechnique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration");

    public String url() {
        return "https://attack.mitre.org/techniques/" + id.replace('.', '/') + "/";
    }
}
