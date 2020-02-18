// Check that OCSP verification works
// @tags: [requires_http_client]

load("jstests/ocsp/lib/mock_ocsp.js");

(function() {
"use strict";

if (determineSSLProvider() != "openssl") {
    return;
}

if (!supportsStapling()) {
    return;
}

let mock_ocsp = new MockOCSPServer();
mock_ocsp.start();

const ocsp_options = {
    sslMode: "requireSSL",
    sslPEMKeyFile: OCSP_SERVER_MUSTSTAPLE_CERT,
    sslCAFile: OCSP_CA_CERT,
    sslAllowInvalidHostnames: "",
    setParameter: {
        "failpoint.disableStapling": "{'mode': 'alwaysOn'}",
        "ocspEnabled": "true",
    },
};

let conn = null;

assert.doesNotThrow(() => {
    conn = MongoRunner.runMongod(ocsp_options);
});

// assert that trying to connect without a stapled OCSP response to a server using a MustStaple
// certificate fails
assert.throws(() => {
    new Mongo(conn.host);
});

MongoRunner.stopMongod(conn);

// The mongoRunner spawns a new Mongo Object to validate the collections which races
// with the shutdown logic of the mock_ocsp responder on some platforms. We need this
// sleep to make sure that the threads don't interfere with each other.
sleep(1000);
mock_ocsp.stop();
}());