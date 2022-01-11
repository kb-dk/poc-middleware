package dk.kb.poc;

import dk.kb.poc.backend.api.v1.PocBackendApi;
import dk.kb.poc.backend.invoker.v1.ApiException;
import dk.kb.poc.config.ServiceConfig;
import dk.kb.util.Resolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

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
class BackendHelperTest {

    static PocBackendApi backend;

    @BeforeAll
    static void setupConfig() throws IOException {
        Path knownFile = Path.of(Resolver.resolveURL("logback-test.xml").getPath());
        String projectRoot = knownFile.getParent().getParent().getParent().toString();

        Path behaviourSetup = Path.of(projectRoot, "conf/poc-middleware-behaviour.yaml");
        assertTrue(Files.exists(behaviourSetup), "The behaviour setup is expected to be present at '" + behaviourSetup + "'");

        ServiceConfig.initialize(projectRoot + File.separator + "conf" + File.separator + "poc-middleware*.yaml");

        backend = BackendHelper.getBackend();
    }

    // Not a unit test as it requires the backend to be running locally
    void testPing() throws ApiException, IOException {
        assertEquals("Pong from backend", BackendHelper.ping());
    }
}