package com.threatlens.domain;

public enum EventType {
    NETWORK_FLOW,
    LOGON_SUCCESS,      // Windows 4624
    LOGON_FAILURE,      // Windows 4625
    PROCESS_CREATE,     // Windows 4688 / Sysmon 1
    ACCOUNT_CREATED,    // Windows 4720
    GROUP_MEMBER_ADDED, // Windows 4728 / 4732 / 4756
    LOG_CLEARED,        // Windows 1102
    OTHER
}
