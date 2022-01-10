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
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dk.kb.poc.webservice.exception.InternalServiceException;
import io.swagger.jackson.mixin.ResponseSchemaMixin;
import io.swagger.models.Response;
import io.swagger.util.DeserializationModule;
import io.swagger.util.Json;
import io.swagger.util.ObjectMapperFactory;
import io.swagger.util.ReferenceSerializationConfigurer;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.QuoteMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper that handles streamed output of a entries as Comma Separated Values.
 * The implementation relies on Jackson and is not very performant due to POJO -> JSON -> CSV conversion.
 *
 * Use the method {@link #write(Object)} and remember to call {@link #close} when finished.
 */
public class CSVStreamWriter extends ExportWriter {
    private static final Logger log = LoggerFactory.getLogger(CSVStreamWriter.class);
    ObjectMapper mapper = createMapper();
    {
        mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS); // We want nulls
    }

    CSVPrinter csvPrinter = null; // Initialized at first write in order to get headers
    private boolean isclosing = false; // If the writer is in the process of closing (breaks infinite recursion)

    private boolean first = true;

    /**
     * Wrap the given inner Writer in the CSVWStreamWriter. Calls to {@link #write(Object)} writes directly to inner,
     * so the JSONStreamWriter holds no cached data. The inner {@link Writer#flush()} is not called during write.
     * @param inner  the Writer to send te result to.
     */
    public CSVStreamWriter(Writer inner) {
        super(inner);
    }

    /**
     * Use {@link #csvPrinter} to serialize the given object to a CSV String and write the result.
     * @param annotatedObject a Jackson annotated Object.
     */
    @Override
    public void write(Object annotatedObject) {
        if (annotatedObject == null) {
            log.warn("Internal inconsistency: write(null) called. This should not happen");
            return;
        }

        ObjectNode nodeBook = mapper.valueToTree(annotatedObject);
        if (first) {
            CSVFormat csvFormat = CSVFormat.DEFAULT
                    .withQuoteMode(QuoteMode.NON_NUMERIC)
                    .withRecordSeparator("\n");
            List<String> headers = new ArrayList<>();
            nodeBook.fieldNames().forEachRemaining(headers::add);
            csvFormat = csvFormat.withHeader(headers.toArray(new String[0]));
            try {
                csvPrinter = new CSVPrinter(this, csvFormat);
            } catch (IOException e) {
                throw new InternalServiceException("Unable to create a CSVPrinter");
            }
            first = false;
        }

        List<Object> elements = new ArrayList<>();
        nodeBook.elements().forEachRemaining(node -> {

            if (node.isNull()) {
                elements.add(null);
            } else if (node.isBoolean()) {
                elements.add(node.booleanValue());
            } else if (node.isInt()) {
                elements.add(node.intValue());
            } else if (node.isLong()) {
                elements.add(node.longValue());
            } else if (node.isDouble()) {
                elements.add(node.doubleValue());
            } else if (node.isFloat()) {
                elements.add(node.floatValue());
            } else if (node.isShort()) {
                elements.add(node.shortValue());
            } else if (node.isArray()) {
                elements.add(getTextArray(node));
            } else if (node.isTextual()) {
                elements.add(normaliseText(node.textValue()));
            } else {
                log.warn("Non-supported node type for CSV export: {} with value '{}'",
                         node.getNodeType(), node.toPrettyString());
                throw new InternalServiceException("Non-supported node type for CSV export: " + node.getNodeType());
            }
        });
        try {
            csvPrinter.printRecord(elements);
        } catch (IOException e) {
            log.warn("IOException writing CSV", e);
            throw new InternalServiceException("Unable to write CSV content", e);
        }
    }

    /**
     * Assumes the given node is an array of text and joins those texts, adding newlines between each entry.
     * @param node an array of text.
     * @return a single line of text with the joined content.
     */
    private static String getTextArray(JsonNode node) {
        if (!node.isArray()) {
            throw new InternalServiceException("Expected an array in CSVStreamWriter.getTextArray but got {}",
                                               node.getNodeType());
        }
        StringBuilder sb = new StringBuilder();
        node.elements().forEachRemaining(sub -> {
            if (!sub.isTextual()) {
                throw new InternalServiceException(
                        "Expectedtext content inside of array in CSVStreamWriter.getTextArray but got {}",
                        node.getNodeType());
            }
            if (sb.length() > 0) {
                sb.append("\\n");
            }
            sb.append(normaliseText(sub.textValue()));
        });
        return sb.toString();
    }

    /**
     * The CSVWriter should handle excaping, but does not seem to do so. Wuotes and newlines re escaped.
     * @param s the String to potentially escape.
     * @return o in escaped form, ready for CSV output.
     */
    protected static Object normaliseText(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\n", "\\n");
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
        try {
            csvPrinter.flush();
        } catch (IOException e) {
            log.warn("IOException while flushing CSVPrinter", e);
        }
        try {
            csvPrinter.close();
        } catch (IOException e) {
            log.warn("IOException while closing CSVPrinter", e);
        }
        super.close();
    }
}
