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

const randomAlgorithm = "AEAD_AES_256_CBC_HMAC_SHA_512-Random";

const conn = MongoRunner.runMongod(x509_options);
const test = conn.getDB("test");
const collection = test.coll;

function runKMS(mock_kms, func) {
    mock_kms.start();

    const gcpKMS = {
        email: "access@mongodb.com",
        endpoint: mock_kms.getURL(),
        privateKey: "secret",
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
    const mock_kms = new MockKMSServerGCP(FAULT_ENCRYPT, false);

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
    const mock_kms = new MockKMSServerGCP(FAULT_ENCRYPT_CORRECT_FORMAT, false);

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
    const mock_kms = new MockKMSServerGCP(FAULT_DECRYPT, false);

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
    const mock_kms = new MockKMSServerGCP(FAULT_DECRYPT_WRONG_KEY, true);

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
    const mock_kms = new MockKMSServerGCP(FAULT_DECRYPT_CORRECT_FORMAT, false);

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