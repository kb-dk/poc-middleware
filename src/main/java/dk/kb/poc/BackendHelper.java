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
package dk.kb.poc;

import com.google.gson.Gson;
import dk.kb.poc.backend.api.v1.PocBackendApi;
import dk.kb.poc.backend.invoker.v1.ApiClient;
import dk.kb.poc.backend.invoker.v1.Configuration;
import dk.kb.poc.backend.model.v1.InternalBookDto;
import dk.kb.poc.config.ServiceConfig;
import dk.kb.poc.model.v1.BookDto;
import dk.kb.poc.webservice.ExportWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 *
 */
public class BackendHelper {
    private static final Logger log = LoggerFactory.getLogger(BackendHelper.class);

    private static URI backendURI = null;
    private static PocBackendApi backend = null;

    public static synchronized PocBackendApi getBackend() {
        if (backend == null) {
            String backendURIString = ServiceConfig.getConfig().getString(".config.backend.url");
            log.info("Creating client for backend with URI '{}'", backendURIString);

            backendURI = URI.create(backendURIString);

            // No mechanism for just providing the full URI. We have to deconstruct it
            ApiClient client = Configuration.getDefaultApiClient();
            client.setScheme(backendURI.getScheme());
            client.setHost(backendURI.getHost());
            client.setPort(backendURI.getPort());
            client.setBasePath(backendURI.getRawPath());

            backend = new PocBackendApi(client);
        }
        return backend;
    }

    // The OpenAPI 4 generator for the backend client does not handle text/plain as response

    /**
     * Send a ping request to the backend and return the response.
     * @return the result of the ping.
     * @throws IOException if the backend could not properly respond to the ping.
     */
    public static String ping() throws IOException {
        return backendStringCall("ping");
    }

    private static String backendStringCall(String subPath) throws IOException {
        getBackend(); // To ensure backendURI is initialized
        URI stringCallURI = UriBuilder.fromUri(backendURI).path(subPath).build();
        try (InputStream in = stringCallURI.toURL().openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }



    /**
     * Convert external book representation to internal representation, adding a dummy secret.
     * @param book a book for public use.
     * @return an internal representation of the book.
     */
    public static InternalBookDto bookToInternalBook(BookDto book) {
        InternalBookDto internal = new InternalBookDto();
        internal.setId(book.getId());
        internal.setTitle(book.getTitle());
        internal.setPages(book.getPages());
        internal.setSecret("Library internal info added by the middleware");
        return internal;
    }


    /**
     * Convert internal book representation to external, stripping secret.
     * @param internal a book for internal use.
     * @return a book suitable for public use.
     */
    public static BookDto internalBookToBook(InternalBookDto internal) {
        BookDto book = new BookDto();
        book.setId(internal.getId());
        book.setTitle(internal.getTitle());
        book.setPages(internal.getPages());
        log.debug("Skipped tranfer of internal information '{}' when transforming InternalBook to Book, id='{}'",
                  internal.getSecret(), internal.getId());
        return book;
    }

    /**
     * Passes the request on to the backend, streaming the result and transforming th internal books to external form
     * before adding to the stated writer.
     * @param writer the receiver of {@link BookDto}s.
     * @param query a query for books.
     * @param max the maximum amount of books to deliver.
     */
    public static void getBooks(ExportWriter writer, String query, Long max) throws IOException {
        URI getBooksURI = UriBuilder.fromUri(backendURI)
                .path("books")
                .queryParam("query", query)
                .queryParam("max", max)
                .build();

        HttpURLConnection urlCon = (HttpURLConnection) getBooksURI.toURL().openConnection();
        urlCon.setRequestProperty("Accept", "application/json");
        urlCon.setRequestProperty("Connection", "close");
        urlCon.setRequestMethod("GET");

        // https://www.amitph.com/java-parse-large-json-files/
        try (InputStream jsonStream = urlCon.getInputStream();
             Reader isReader = new InputStreamReader(jsonStream, StandardCharsets.UTF_8);
             JsonReader reader = new JsonReader(isReader)) {
            reader.beginArray();
            while (reader.hasNext()) {
                InternalBookDto internal = new Gson().fromJson(reader, InternalBookDto.class);
                writer.write(internalBookToBook(internal));
            }
            reader.endArray();
        }
    }

}
