package com.threatlens.detection;

import com.threatlens.domain.SecurityEvent;

import java.time.Duration;
import java.util.*;
import java.util.function.Function;

/** Sliding-window helpers shared by threshold rules. */
public final class Windows {

    private Windows() {}

    /**
     * Finds bursts of activity: a burst starts when the events inside a sliding
     * {@code window} reach {@code threshold} (event count, or distinct values of
     * {@code distinctBy} when given) and keeps extending while consecutive events
     * are no further apart than {@code window}. Each burst becomes one alert,
     * instead of one alert per overlapping window.
     */
    public static List<List<SecurityEvent>> bursts(List<SecurityEvent> sorted, Duration window, int threshold,
                                                   Function<SecurityEvent, ?> distinctBy) {
        List<List<SecurityEvent>> out = new ArrayList<>();
        Map<Object, Integer> distinct = new HashMap<>();
        int i = 0;
        int j = 0;
        while (j < sorted.size()) {
            SecurityEvent cur = sorted.get(j);
            add(distinct, distinctBy, cur);
            while (Duration.between(sorted.get(i).getEventTime(), cur.getEventTime()).compareTo(window) > 0) {
                remove(distinct, distinctBy, sorted.get(i));
                i++;
            }
            int metric = distinctBy == null ? j - i + 1 : distinct.size();
            if (metric >= threshold) {
                int k = j + 1;
                while (k < sorted.size() && Duration.between(sorted.get(k - 1).getEventTime(),
                        sorted.get(k).getEventTime()).compareTo(window) <= 0) {
                    k++;
                }
                out.add(List.copyOf(sorted.subList(i, k)));
                distinct.clear();
                i = j = k;
                continue;
            }
            j++;
        }
        return out;
    }

    private static void add(Map<Object, Integer> m, Function<SecurityEvent, ?> f, SecurityEvent e) {
        if (f == null) return;
        Object key = f.apply(e);
        if (key != null) m.merge(key, 1, Integer::sum);
    }

    private static void remove(Map<Object, Integer> m, Function<SecurityEvent, ?> f, SecurityEvent e) {
        if (f == null) return;
        Object key = f.apply(e);
        if (key != null) m.computeIfPresent(key, (k, v) -> v == 1 ? null : v - 1);
    }

    /** Groups events by a key, preserving time order within each group and skipping null keys. */
    public static <K> Map<K, List<SecurityEvent>> groupBy(List<SecurityEvent> sorted, Function<SecurityEvent, K> key) {
        Map<K, List<SecurityEvent>> groups = new LinkedHashMap<>();
        for (SecurityEvent e : sorted) {
            K k = key.apply(e);
            if (k != null) groups.computeIfAbsent(k, x -> new ArrayList<>()).add(e);
        }
        return groups;
    }

    /** Top-N most frequent values with counts, for evidence. */
    public static <T> Map<T, Long> topCounts(List<SecurityEvent> events, Function<SecurityEvent, T> f, int n) {
        Map<T, Long> counts = new HashMap<>();
        for (SecurityEvent e : events) {
            T v = f.apply(e);
            if (v != null) counts.merge(v, 1L, Long::sum);
        }
        Map<T, Long> top = new LinkedHashMap<>();
        counts.entrySet().stream()
                .sorted(Map.Entry.<T, Long>comparingByValue().reversed())
                .limit(n)
                .forEach(en -> top.put(en.getKey(), en.getValue()));
        return top;
    }

    public static <T> Set<T> distinct(List<SecurityEvent> events, Function<SecurityEvent, T> f) {
        Set<T> s = new TreeSet<>();
        for (SecurityEvent e : events) {
            T v = f.apply(e);
            if (v != null) s.add(v);
        }
        return s;
    }
}
