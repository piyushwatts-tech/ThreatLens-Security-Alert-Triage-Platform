package com.threatlens.alert;

import java.util.List;
import java.util.Map;

/** First-response steps per rule, shown to analysts and given to the LLM as grounding. */
public final class Playbooks {

    private Playbooks() {}

    private static final Map<String, List<String>> STEPS = Map.of(
            "NET-001", List.of("Confirm whether the source is an authorised scanner (vuln mgmt, IT asset discovery).",
                    "Check which probed ports are open on the target and whether follow-up connections succeeded.",
                    "Block the source at the perimeter if external and unauthorised."),
            "NET-002", List.of("Check the target service's auth logs for any successful logon from the source.",
                    "Block or rate-limit the source; enforce key-based auth / MFA on the service.",
                    "Hunt for the same source hitting other hosts."),
            "NET-003", List.of("Confirm service availability impact with the service owner.",
                    "Engage upstream DDoS mitigation / rate limiting; block top sources.",
                    "Preserve flow samples for the incident record."),
            "WIN-001", List.of("Check whether any logon from the source succeeded (see WIN-003).",
                    "Verify account lockout fired; reset the password if the account is exposed.",
                    "Identify the source machine and why it is attempting these logons."),
            "WIN-002", List.of("List every targeted account and check for any subsequent successful logon.",
                    "Block the source; force password resets for accounts with weak/common passwords.",
                    "Review MFA coverage for the targeted accounts."),
            "WIN-003", List.of("Treat as compromised credentials: disable or reset the account now.",
                    "Isolate the host the account logged on to and review its process/network activity.",
                    "Scope lateral movement from that host in the following hours."),
            "WIN-004", List.of("Decode and review the command; retrieve any downloaded payload hash.",
                    "Isolate the endpoint and collect the parent document if Office spawned it.",
                    "Block the download domain/IP and search for it fleet-wide."),
            "WIN-005", List.of("Confirm the change with the requester / change ticket.",
                    "If unapproved, remove the membership and disable the account.",
                    "Investigate the actor account that made the change."),
            "WIN-006", List.of("Treat as hostile until proven otherwise; isolate the host.",
                    "Pull forwarded logs from the SIEM for the period before the clear.",
                    "Investigate the account that cleared the log."),
            "ML-001", List.of("Identify the process on the source host that owns these connections.",
                    "Check destination reputation and whether the volume matches a sanctioned transfer.",
                    "If unexplained, block the destination and isolate the host."));

    public static List<String> forRule(String ruleId) {
        return STEPS.getOrDefault(ruleId, List.of("Review evidence and escalate per runbook."));
    }
}
