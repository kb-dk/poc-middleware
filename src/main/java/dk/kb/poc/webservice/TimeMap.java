/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package dk.kb.poc.webservice;

import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Map where entries are removed (lazily) when they have been kept for more than a given amount of seconds.
 */
class TimeMap<K, V> extends AbstractMap<K, V> {
    private final long ttlSeconds;
    private final Map<K, TimeValue<V>> inner = new HashMap<>();

    /**
     * @param ttlSeconds time to live in seconds, -1 means forever.
     */
    public TimeMap(long ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
    }

    @Override
    public Set<Entry<K, V>> entrySet() {
        return inner.entrySet().stream()
                .map(entry -> new AbstractMap.SimpleImmutableEntry<>(entry.getKey(), entry.getValue().getValue()))
                .collect(Collectors.toSet());
    }

    @Override
    public V put(K key, V value) {
        TimeValue<V> oldWrapped = inner.put(key, new TimeValue<>(value));
        return oldWrapped == null ? null : oldWrapped.getValue();
    }

    @Override
    public V get(Object key) {
        TimeValue<V> wrapped = inner.get(key);
        if (wrapped == null) {
            return null;
        }
        if (wrapped.isExpired()) {
            remove(key);
            return null;
        }
        return wrapped.getValue();
    }

    @Override
    public Set<K> keySet() {
        return inner.keySet();
    }

    @Override
    public V remove(Object key) {
        TimeValue<V> oldWrapped = inner.remove(key);
        return oldWrapped == null ? null : oldWrapped.getValue();
    }

    @Override
    public void clear() {
        inner.clear();
    }

    @Override
    public boolean containsKey(Object key) {
        return inner.containsKey(key);
    }

    @Override
    public int size() {
        return inner.size();
    }

    @Override
    public boolean isEmpty() {
        return inner.isEmpty();
    }

    /**
     * Holds a value and an expiry time.
     */
    private class TimeValue<V> {
        public final V value;
        private final long expiryTime; // Epoch

        /**
         * @param value      the value to hold.
         */
        public TimeValue(V value) {
            this.value = value;
            this.expiryTime = ttlSeconds == -1 ? Long.MAX_VALUE : System.currentTimeMillis() + ttlSeconds;
        }

        /**
         * @return true if the entry is expired, else false.
         */
        public boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }

        /**
         * @return the stored value for the entry.
         */
        public V getValue() {
            return value;
        }
    }

}
