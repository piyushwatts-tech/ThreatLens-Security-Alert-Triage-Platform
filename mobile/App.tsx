import { StatusBar } from "expo-status-bar";
import { useCallback, useEffect, useState } from "react";
import {
  ActivityIndicator, Alert as RNAlert, FlatList, Pressable, RefreshControl, SafeAreaView, StyleSheet, Text, View,
} from "react-native";

/**
 * ThreatLens on-call screen: open CRITICAL (and optionally HIGH) alerts,
 * pull-to-refresh, 30s polling, and one-tap "Acknowledge" (-> INVESTIGATING).
 *
 * Point it at your backend with EXPO_PUBLIC_API_URL, e.g. http://192.168.1.20:8080
 * (a phone cannot reach "localhost" on your laptop).
 */
const API = process.env.EXPO_PUBLIC_API_URL ?? "http://localhost:8080";
const ANALYST = process.env.EXPO_PUBLIC_ANALYST ?? "on-call";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Status = "NEW" | "INVESTIGATING" | "CLOSED";

interface AlertRow {
  id: number;
  ruleId: string;
  title: string;
  severity: Severity;
  riskScore: number;
  status: Status;
  assignee: string | null;
  mitreTechnique: string | null;
  mitreTactic: string | null;
  srcIp: string | null;
  dstIp: string | null;
  host: string | null;
  username: string | null;
  firstSeen: string;
}

const COLORS = {
  bg: "#121211", card: "#1a1a19", border: "#2e2e2c", text: "#f0efec", text2: "#c3c2b7", text3: "#8d8c84",
  critical: "#d03b3b", high: "#ec835a", blue: "#3987e5",
};

function ago(iso: string) {
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 60) return `${m}m ago`;
  if (m < 1440) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
}

export default function App() {
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [includeHigh, setIncludeHigh] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const sev = includeHigh ? "&severity=CRITICAL&severity=HIGH" : "&severity=CRITICAL";
    try {
      const res = await fetch(`${API}/api/alerts?status=NEW&status=INVESTIGATING${sev}&sort=riskScore&size=50`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setAlerts(body.items);
      setError(null);
    } catch (e) {
      setError(`Cannot reach ${API}: ${(e as Error).message}`);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [includeHigh]);

  useEffect(() => {
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, [load]);

  async function acknowledge(a: AlertRow) {
    try {
      const res = await fetch(`${API}/api/alerts/${a.id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "INVESTIGATING", actor: ANALYST, note: "Acknowledged from mobile" }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      load();
    } catch (e) {
      RNAlert.alert("Could not acknowledge", (e as Error).message);
    }
  }

  const critical = alerts.filter((a) => a.severity === "CRITICAL").length;

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <Text style={styles.brand}>ThreatLens</Text>
        <Text style={styles.headline}>
          <Text style={{ color: COLORS.critical }}>▲ {critical}</Text> open critical
        </Text>
        <Pressable onPress={() => setIncludeHigh((v) => !v)} style={[styles.toggle, includeHigh && styles.toggleOn]}
                   accessibilityRole="switch" accessibilityState={{ checked: includeHigh }}>
          <Text style={styles.toggleText}>{includeHigh ? "Critical + High" : "Critical only"}</Text>
        </Pressable>
      </View>

      {error && <Text style={styles.error}>{error}</Text>}
      {loading ? (
        <ActivityIndicator color={COLORS.blue} style={{ marginTop: 40 }} />
      ) : (
        <FlatList
          data={alerts}
          keyExtractor={(a) => String(a.id)}
          contentContainerStyle={{ padding: 16, gap: 12 }}
          refreshControl={<RefreshControl refreshing={refreshing} tintColor={COLORS.text2}
                                          onRefresh={() => { setRefreshing(true); load(); }} />}
          ListEmptyComponent={<Text style={styles.empty}>Nothing open. Quiet shift.</Text>}
          renderItem={({ item: a }) => {
            const color = a.severity === "CRITICAL" ? COLORS.critical : COLORS.high;
            return (
              <View style={[styles.card, { borderLeftColor: color }]}>
                <View style={styles.row}>
                  <Text style={[styles.sev, { color, borderColor: color }]}>
                    {a.severity === "CRITICAL" ? "▲" : "◆"} {a.severity} {a.riskScore}
                  </Text>
                  <Text style={styles.meta}>{ago(a.firstSeen)}</Text>
                </View>
                <Text style={styles.title}>{a.title}</Text>
                <Text style={styles.meta}>
                  {a.ruleId} · {a.mitreTechnique ?? "n/a"} {a.mitreTactic ? `(${a.mitreTactic})` : ""}
                </Text>
                <Text style={styles.entities}>
                  {[a.srcIp, a.dstIp ?? a.host, a.username].filter(Boolean).join("  ·  ")}
                </Text>
                {a.status === "NEW" ? (
                  <Pressable style={styles.ack} onPress={() => acknowledge(a)} accessibilityRole="button">
                    <Text style={styles.ackText}>Acknowledge</Text>
                  </Pressable>
                ) : (
                  <Text style={styles.meta}>Investigating{a.assignee ? ` by ${a.assignee}` : ""}</Text>
                )}
              </View>
            );
          }}
        />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: COLORS.bg },
  header: { paddingHorizontal: 16, paddingTop: 12, paddingBottom: 8, borderBottomWidth: 1, borderColor: COLORS.border },
  brand: { color: COLORS.text3, fontSize: 13, fontWeight: "600", letterSpacing: 1 },
  headline: { color: COLORS.text, fontSize: 26, fontWeight: "700", marginTop: 4 },
  toggle: { alignSelf: "flex-start", marginTop: 10, paddingHorizontal: 12, paddingVertical: 6, borderRadius: 999,
            borderWidth: 1, borderColor: COLORS.border },
  toggleOn: { borderColor: COLORS.blue },
  toggleText: { color: COLORS.text2, fontSize: 13 },
  error: { color: COLORS.critical, padding: 16 },
  empty: { color: COLORS.text3, textAlign: "center", marginTop: 40 },
  card: { backgroundColor: COLORS.card, borderRadius: 10, padding: 14, borderWidth: 1, borderColor: COLORS.border,
          borderLeftWidth: 4, gap: 6 },
  row: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  sev: { fontSize: 11, fontWeight: "700", borderWidth: 1, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
  title: { color: COLORS.text, fontSize: 15, fontWeight: "600" },
  meta: { color: COLORS.text3, fontSize: 12 },
  entities: { color: COLORS.text2, fontSize: 12, fontFamily: "Courier" },
  ack: { marginTop: 6, backgroundColor: COLORS.blue, borderRadius: 8, paddingVertical: 10, alignItems: "center" },
  ackText: { color: "#fff", fontWeight: "600" },
});
