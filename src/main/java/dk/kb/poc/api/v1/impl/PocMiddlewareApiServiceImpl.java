package dk.kb.poc.api.v1.impl;

import dk.kb.poc.backend.api.v1.PocBackendApi;
import dk.kb.poc.backend.invoker.v1.ApiClient;
import dk.kb.poc.api.v1.PocMiddlewareApi;
import dk.kb.poc.backend.invoker.v1.Configuration;
import dk.kb.poc.model.v1.BookDto;
import dk.kb.poc.webservice.ExportWriter;
import dk.kb.poc.webservice.ExportWriterFactory;
import dk.kb.poc.webservice.exception.InternalServiceException;
import dk.kb.poc.webservice.exception.InvalidArgumentServiceException;
import dk.kb.poc.webservice.exception.ServiceException;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.Providers;
import java.util.Locale;

/**
 * poc-middleware
 *
 * <p>poc-middleware by the Royal Danish Library
 *
 */
public class PocMiddlewareApiServiceImpl implements PocMiddlewareApi {
    private static final Logger log = LoggerFactory.getLogger(PocMiddlewareApiServiceImpl.class);

    /* How to access the various web contexts. See https://cxf.apache.org/docs/jax-rs-basics.html#JAX-RSBasics-Contextannotations */

    @Context
    private transient UriInfo uriInfo;

    @Context
    private transient SecurityContext securityContext;

    @Context
    private transient HttpHeaders httpHeaders;

    @Context
    private transient Providers providers;

    @Context
    private transient Request request;

    // Disabled as it is always null? TODO: Investigate when it can be not-null, then re-enable with type
    //@Context
    //private transient ContextResolver contextResolver;

    @Context
    private transient HttpServletRequest httpServletRequest;

    @Context
    private transient HttpServletResponse httpServletResponse;

    @Context
    private transient ServletContext servletContext;

    @Context
    private transient ServletConfig servletConfig;

    @Context
    private transient MessageContext messageContext;


    /**
     * Add or update a single book
     *
     * @param bookDto: Add or update a single book
     *
     * @return <ul>
      *   <li>code = 200, message = "If the book was added successfully", response = BookDto.class</li>
      *   </ul>
      * @throws ServiceException when other http codes should be returned
      *
      * @implNote return will always produce a HTTP 200 code. Throw ServiceException if you need to return other codes
     */
    @Override
    public BookDto addBook(BookDto bookDto) throws ServiceException {
        log.info("addBook({}) begin", bookDto);
        try {
            throw new UnsupportedOperationException("Not implemented yet (generate client Dto's for the backend serice and call that)");
        } catch (Exception e){
            throw handleException(e);
        } finally {
            log.info("addBook({}) finish", bookDto);
        }
    }

    /**
     * Deletes metadata for a single book
     *
     * @param id: The ID for the book to delete
     *
     * @return <ul>
      *   <li>code = 200, message = "OK", response = String.class</li>
      *   <li>code = 404, message = "Not found"</li>
      *   </ul>
      * @throws ServiceException when other http codes should be returned
      *
      * @implNote return will always produce a HTTP 200 code. Throw ServiceException if you need to return other codes
     */
    @Override
    public String deleteBook(String id) throws ServiceException {
        log.info("deleteBook({}) begin", id);
        try {
            throw new UnsupportedOperationException("Not implemented yet (generate client Dto's for the backend serice and call that)");
        } catch (Exception e){
            throw handleException(e);
        } finally {
            log.info("deleteBook({}) finish", id);
        }
    }

    /**
     * Retrieves metadata for a single book
     *
     * @param id: The ID for the book to retrieve
     *
     * @return <ul>
      *   <li>code = 200, message = "JSON-compliant representation of the Book.", response = BookDto.class</li>
      *   <li>code = 404, message = "Not found"</li>
      *   </ul>
      * @throws ServiceException when other http codes should be returned
      *
      * @implNote return will always produce a HTTP 200 code. Throw ServiceException if you need to return other codes
     */
    @Override
    public BookDto getBook(String id) throws ServiceException {
        log.info("getBook({}) begin", id);
        try {

            ApiClient defaultClient = Configuration.getDefaultApiClient();
            defaultClient.setBasePath("http://localhost/poc-backend/v1");

            // Not working below as it is an interface
            PocBackendApi apiInstance = new PocBackendApi(defaultClient);

            //new ApiClient().setBasePath("http://localhost:9060/poc-backend/v1/").;
            throw new UnsupportedOperationException("Not implemented yet (generate client Dto's for the backend serice and call that)");
        } catch (Exception e){
            throw handleException(e);
        } finally {
            log.info("getBook({}) finish", id);
        }
    }

    /**
     * Delivers metadata on books
     *
     * @param query: Search query for the books
     *
     * @param max: The maximum number of books to return
     *
     * @param format: The delivery format. This can also be specified using headers, as seen in the Responses section. If both headers and format are specified, format takes precedence.  * JSONL: Newline separated single-line JSON representations of Documents * JSON: Valid JSON in the form of a single array of Documents * CSV: Comma separated, missing values represented with nothing, strings encapsulated in quotes
     *
     * @return <ul>
      *   <li>code = 200, message = "OK", response = String.class</li>
      *   <li>code = 400, message = "Bad request"</li>
      *   </ul>
      * @throws ServiceException when other http codes should be returned
      *
      * @implNote return will always produce a HTTP 200 code. Throw ServiceException if you need to return other codes
     */
    @Override
    public javax.ws.rs.core.StreamingOutput getBooks(String query, Long max, String format) throws ServiceException {
        log.info("getBooks(query='{}', max={}, format={}) begin", query, max, format);
        if (max < 0) {
            throw new InvalidArgumentServiceException("max must be positive but was " + max); // HTTP 400
        }

        try {
            String filename = "book_export." + (format == null ? "jsonl" : format.toLowerCase(Locale.ROOT));
            if (max <= 100) {
                // A few books is ok to show inline in the Swagger GUI
                // Show inline in Swagger UI, inline when opened directly in browser
                 httpServletResponse.setHeader("Content-Disposition", "inline; filename=\"" + filename + "\"");
            } else {
                // Many books should not be displayed inline
                // Show download link in Swagger UI, inline when opened directly in browser
                // https://github.com/swagger-api/swagger-ui/issues/3832
                httpServletResponse.setHeader("Content-Disposition", "inline; swaggerDownload=\"attachment\"; filename=\"" + filename + "\"");
            }

            return output -> {
                try (ExportWriter writer = ExportWriterFactory.wrap(
                        output, httpServletResponse, httpHeaders,
                        format, ExportWriterFactory.FORMAT.jsonl, false)) {
                    throw new UnsupportedOperationException("Not implemented yet (generate client Dto's for the backend serice and call that)");
                }
            };
        } catch (Exception e){
            throw handleException(e);
        } finally {
            log.info("getBooks(query='{}', max={}, format={}) finish", query, max, format);
        }
    }

    /**
     * Ping the server to check if the server is reachable.
     *
     * @return <ul>
      *   <li>code = 200, message = "OK", response = String.class</li>
      *   <li>code = 406, message = "Not Acceptable", response = ErrorDto.class</li>
      *   <li>code = 500, message = "Internal Error", response = String.class</li>
      *   </ul>
      * @throws ServiceException when other http codes should be returned
      *
      * @implNote return will always produce a HTTP 200 code. Throw ServiceException if you need to return other codes
     */
    @Override
    public String ping() throws ServiceException {
        log.info("ping begin");
        try {
            // TODO: Add piped ping from backend?
            return "Pong from middleware";
        } catch (Exception e){
            throw handleException(e);
        } finally {
            log.info("ping finish");
        }
    }


    /**
    * This method simply converts any Exception into a Service exception
    * @param e: Any kind of exception
    * @return A ServiceException
    * @see dk.kb.poc.webservice.ServiceExceptionMapper
    */
    private ServiceException handleException(Exception e) {
        if (e instanceof ServiceException) {
            return (ServiceException) e; // Do nothing - this is a declared ServiceException from within module.
        } else {// Unforseen exception (should not happen). Wrap in internal service exception
            log.error("ServiceException(HTTP 500):", e); //You probably want to log this.
            return new InternalServiceException(e.getMessage());
        }
    }

}
