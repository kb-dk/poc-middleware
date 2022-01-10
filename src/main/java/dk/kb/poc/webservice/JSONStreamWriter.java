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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import dk.kb.poc.webservice.exception.InternalServiceException;
import io.swagger.util.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Writer;

/**
 * Wrapper that handles streamed output of a entries, either as a single valid JSON or
 * JSON Lines (1 independent JSON/line).
 *
 * Use the method {@link #write(Object)} and remember to call {@link #close} when finished.
 */
public class JSONStreamWriter extends ExportWriter {
    private static final Logger log = LoggerFactory.getLogger(JSONStreamWriter.class);
    private final ObjectWriter jsonWriter;

    public enum FORMAT { json, jsonl }

    private final FORMAT format;
    private boolean first = true;
    private boolean isclosing = false; // If the writer is in the process of closing (breaks infinite recursion)

    /**
     * Wrap the given inner Writer in the JSONStreamWriter. Calls to {@link #write(Object)} writes directly to inner,
     * so the JSONStreamWriter holds no cached data. The inner {@link Writer#flush()} is not called during write.
     * null-values in objects given to {@link #write(Object)} will not be written. To control this, use
     * the {@link JSONStreamWriter(Writer, FORMAT, boolean)} constructor.
     * @param inner  the Writer to send te result to.
     * @param format Valid JSON or JSON Lines.
     */
    public JSONStreamWriter(Writer inner, FORMAT format) {
        this(inner, format, false);
    }

    /**
     * Wrap the given inner Writer in the JSONStreamWriter. Calls to {@link #write} writes directly to inner,
     * so the JSONStreamWriter holds no cached data. The inner {@link Writer#flush()} is not called.
     * @param inner  the Writer to send te result to.
     * @param format Valid JSON or JSON Lines.
     * @param writeNulls if true, null values are written as {@code "key" : null}, if false they are skipped.
     */
    public JSONStreamWriter(Writer inner, FORMAT format, boolean writeNulls) {
        super(inner);
        this.format = format;
        if (inner == null) {
            throw new IllegalArgumentException("Inner Writer was null, but must be defined");
        }
        if (format == null) {
            throw new IllegalArgumentException("Format was null, but must be defined");
        }

        ObjectMapper mapper = createMapper();
        mapper.setSerializationInclusion(writeNulls ? JsonInclude.Include.ALWAYS : JsonInclude.Include.NON_NULL);
        jsonWriter = mapper.writer(new MinimalPrettyPrinter());
    }

    /**
     * Write a JSON expression that has already been serialized to String.
     * It is the responsibility of the caller to ensure that jsonStr is valid standalone JSON.
     * If {@link #format} is {@link FORMAT#jsonl}, newlines in jsonStr will be replaced by spaces.
     * @param jsonStr a valid JSON.
     */
    @Override
    public void write(String jsonStr) {
        if (format == FORMAT.jsonl) {
            jsonStr = jsonStr.replace("\n", " ");
        }

        if (first) {
            super.write(format == FORMAT.json ? "[\n" : "");
            first = false;
        } else {
            super.write(format == FORMAT.json ? ",\n" : "\n");
        }
        super.write(jsonStr);
    }

    /**
     * Use {@link #jsonWriter} to serialize the given object to String JSON and write the result, ensuring the
     * invariants of {@link #format} holds.
     * @param annotatedObject a Jackson annotated Object.
     */
    @Override
    public void write(Object annotatedObject) {
        if (annotatedObject == null) {
            log.warn("Internal inconsistency: write(null) called. This should not happen");
            return;
        }
        try {
            write(jsonWriter.writeValueAsString(annotatedObject));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JsonProcessingException attempting to write " + annotatedObject, e);
        }
    }

    /**
     * Finishes the JSON stream by writing closing statements (if needed).
     */
    @Override
    public void close() {
        if (isclosing) {
            return; // Avoid infinite recursion
        }
        isclosing = true;
        if (format == FORMAT.json) {
            super.write(first ? "[\n]\n" : "\n]\n");
        } else {
            super.write("\n");
        }
        super.close();
    }
}
