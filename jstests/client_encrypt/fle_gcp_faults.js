/**
 * Verify the GCP KMS implementation can handle a buggy KMS.
 */

load("jstests/client_encrypt/lib/mock_kms.js");
load('jstests/ssl/libs/ssl_helpers.js');

(function() {
"use strict";

const x509_options = {
    sslMode: "requireSSL",
    sslPEMKeyFile: SERVER_CERT,
    sslCAFile: CA_CERT
};

jsTestLog(x509_options);

const randomAlgorithm = "AEAD_AES_256_CBC_HMAC_SHA_512-Random";

const conn = MongoRunner.runMongod(x509_options);
const test = conn.getDB("test");
const collection = test.coll;

function runKMS(mock_kms, func) {
    mock_kms.start();

    const gcpKMS = {
        email: "access@mongodb.com",
        endpoint: mock_kms.getURL(),
        // "secret" encoded in base64
        privateKey:
            "MIIBOgIBAAJBAMvDlRJYwlmmu/s4FdwSRFyQmrno1kaRlvvsz6BG5EUAAQyzKDaaDN5j+sk7OYcPmMvJDhJYvcEo1d7+ZTiBzEcCAwEA" +
            "AQJBAIvkkTnxWi02vaRyEv/uQqTSWof8hPAaEHCRWtKNGTcM2PsmsMX1zQuLbK4rHNnqgCbjCjBUR/5usWRwSxHy5HECIQD4J88vHffW" +
            "LMMBkxF4l9yUdV34M7ghsnxmxd8E6guK0wIhANI0iTwmlNZWdIk68Y6QUomGOjGgmJ6XQV3//7XdtGg9AiA3du5f4ZrbS/XqDC0Dfy3W" +
            "IMV4DFdDcNlNPzyxpH4f8QIgEbLWszfUZE+XNE7AM+625Flm4PLSpte5az64uwlVvUkCIHVdtaKcYU+G21NZZlv3JoxHUGnF6IsL/42P" +
            "oYbL7FyQ",
    };

    const clientSideFLEOptions = {
        kmsProviders: {
            gcp: gcpKMS,
        },
        keyVaultNamespace: "test.coll",
        schemaMap: {},
    }

    const shell = Mongo(conn.host, clientSideFLEOptions);
    const cleanCacheShell = Mongo(conn.host, clientSideFLEOptions);

    collection.drop();

    func(shell, cleanCacheShell);

    mock_kms.stop();
}

function testBadEncryptResult() {
    const mock_kms = new MockKMSServerAWS(FAULT_ENCRYPT, false);

    runKMS(mock_kms, (shell) => {
        const keyVault = shell.getKeyVault();

        assert.throws(
            () => keyVault.createKey(
                "gcp",
                "projects/mock/locations/global/keyRings/mock-key-ring/cryptoKeys/mock-key",
                ["mongoKey"]));
        assert.eq(keyVault.getKeys("mongoKey").toArray().length, 0);
    });
}

testBadEncryptResult();

function testBadEncryptError() {
    const mock_kms = new MockKMSServerAWS(FAULT_ENCRYPT_CORRECT_FORMAT, false);

    runKMS(mock_kms, (shell) => {
        const keyVault = shell.getKeyVault();
        let error = assert.throws(
            () => keyVault.createKey(
                "gcp",
                "projects/mock/locations/global/keyRings/mock-key-ring/cryptoKeys/mock-key",
                ["mongoKey"]));
        assert.commandFailedWithCode(error, [5256006]);
    })
}

testBadEncryptError();

function testBadDecryptResult() {
    const mock_kms = new MockKMSServerAWS(FAULT_DECRYPT, false);

    runKMS(mock_kms, (shell) => {
        const keyVault = shell.getKeyVault();
        const keyId = keyVault.createKey(
            "gcp",
            "projects/mock/locations/global/keyRings/mock-key-ring/cryptoKeys/mock-key",
            ["mongoKey"]);
        const str = "mongo";
        assert.throws(() => {
            const encStr = shell.getClientEncryption().encrypt(keyId, str, randomAlgorithm);
        });
    });
}

testBadDecryptResult();

function testBadDecryptKeyResult() {
    const mock_kms = new MockKMSServerAWS(FAULT_DECRYPT_WRONG_KEY, true);

    runKMS(mock_kms, (shell, cleanCacheShell) => {
        const keyVault = shell.getKeyVault();

        keyVault.createKey(
            "gcp",
            "projects/mock/locations/global/keyRings/mock-key-ring/cryptoKeys/mock-key",
            ["mongoKey"]);
        const keyId = keyVault.getKeys("mongoKey").toArray()[0]._id;
        const str = "mongo";
        const encStr = shell.getClientEncryption().encrypt(keyId, str, randomAlgorithm);

        mock_kms.enableFaults();

        assert.throws(() => {
            let str = cleanCacheShell.decrypt(encStr);
        });
    });
}

testBadDecryptKeyResult();

function testBadDecryptError() {
    const mock_kms = new MockKMSServerAWS(FAULT_DECRYPT_CORRECT_FORMAT, false);

    runKMS(mock_kms, (shell) => {
        const keyVault = shell.getKeyVault();

        keyVault.createKey(
            "gcp",
            "projects/mock/locations/global/keyRings/mock-key-ring/cryptoKeys/mock-key",
            ["mongoKey"]);
        const keyId = keyVault.getKeys("mongoKey").toArray()[0]._id;
        const str = "mongo";
        let error = assert.throws(() => {
            const encStr = shell.getClientEncryption().encrypt(keyId, str, randomAlgorithm);
        });
        assert.commandFailedWithCode(error, [5256008]);
    });
}

testBadDecryptError();

MongoRunner.stopMongod(conn);
})();