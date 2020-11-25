/**
 *    Copyright (C) 2020-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kControl

#include "mongo/platform/basic.h"

#include <kms_message/kms_b64.h>
#include <kms_message/kms_gcp_request.h>
#include <kms_message/kms_message.h>

#include "mongo/bson/json.h"
#include "mongo/shell/kms.h"
#include "mongo/shell/kms_network.h"
#include "mongo/util/net/ssl_manager.h"
#include "mongo/util/net/ssl_options.h"

namespace mongo {
namespace {

// Default endpoints for GCP
static constexpr StringData defaultOauthEndpoint = "oauth2.googleapis.com"_sd;
static constexpr StringData defaultOauthScope = "https://www.googleapis.com/auth/cloudkms"_sd;
static constexpr StringData gcpKMSEndpoint = "https://cloudkms.googleapis.com:443"_sd;

// Field names for BSON objects containing key vault information
static constexpr StringData kProjectIdField = "projectID"_sd;
static constexpr StringData kLocationIdField = "locationID"_sd;
static constexpr StringData kKeyRingField = "keyRing"_sd;
static constexpr StringData kKeyNameField = "key"_sd;
static constexpr StringData kKeyVerisionField = "keyVersion"_sd;

class UniqueBytes {
public:
    ~UniqueBytes() {
        std::free((void*)_bytes);
    }
    UniqueBytes(const uint8_t* bytes) : _bytes(bytes) {}
    UniqueBytes& operator=(UniqueBytes) = delete;
    UniqueBytes& operator=(UniqueBytes&&) = delete;
    UniqueBytes(UniqueBytes&) = delete;
    UniqueBytes(UniqueBytes&&) = delete;
    const uint8_t* get() const {
        return _bytes;
    }
    const uint8_t** getPtr() {
        return &_bytes;
    }

private:
    const uint8_t* _bytes;
};

/**
 * GCP configuration settings
 */
struct GCPConfig {
    // E-mail address that will be used for GCP OAuth requests.
    std::string email;

    // PKCS#8 private key
    std::string privateKey;

    // Options to pass to GCP KMS requests
    UniqueKmsRequestOpts opts;
};

void uassertKmsRequestInternal(kms_request_t* request, bool ok) {
    if (!ok) {
        const char* msg = kms_request_get_error(request);
        uasserted(5265000, str::stream() << "Internal GCP KMS Error: " << msg);
    }
}

#define uassertKmsRequest(X) uassertKmsRequestInternal(request, (X))

/**
 * Manages OAuth token requests and caching
 */
class GCPKMSOAuthService final : public KMSOAuthService {
public:
    GCPKMSOAuthService(const GCPConfig& config,
                       HostAndPort endpoint,
                       std::shared_ptr<SSLManagerInterface> sslManager)
        : KMSOAuthService(endpoint, sslManager), _config(config) {}

protected:
    UniqueKmsRequest getOAuthRequest() {
        std::string audience = str::stream() << "https://" << _oAuthEndpoint.host() << "/token";
        std::string scope;
        if (_oAuthEndpoint.host() != defaultOauthEndpoint.toString()) {
            // TODO Scope is supposed to derive from a KMS endpoint as opposed to OAuth. Where could
            // I derive that from in this function?
            scope = str::stream() << "https://www." << _oAuthEndpoint.host() << "/auth/cloudkms";
        } else {
            scope = defaultOauthScope.toString();
        }
        size_t decodeLen;
        UniqueBytes privateKeyDecoded(
            kms_message_b64_to_raw(_config.privateKey.c_str(), &decodeLen));

        if (privateKeyDecoded.get() == nullptr) {
            uasserted(5265004, "Internal GCP KMS Error: Private key must be encoded as base64");
        }

        auto request = UniqueKmsRequest(
            kms_gcp_request_oauth_new(_oAuthEndpoint.toString().c_str(),
                                      _config.email.c_str(),
                                      audience.c_str(),
                                      scope.c_str(),
                                      reinterpret_cast<const char*>(privateKeyDecoded.get()),
                                      decodeLen,
                                      _config.opts.get()));

        const char* msg = kms_request_get_error(request.get());
        uassert(5265003, str::stream() << "Internal GCP KMS Error: " << msg, msg == nullptr);

        return request;
    }

private:
    const GCPConfig& _config;
};

/**
 * Manages SSL information and config for how to talk to GCP KMS.
 */
class GCPKMSService final : public KMSService {
public:
    GCPKMSService() = default;

    static std::unique_ptr<KMSService> create(const GcpKMS&);

    std::vector<uint8_t> encrypt(ConstDataRange cdr, StringData kmsKeyId) final;

    SecureVector<uint8_t> decrypt(ConstDataRange cdr, BSONObj masterKey) final;

    BSONObj encryptDataKey(ConstDataRange cdr, StringData keyId) final;

    void configureOauthService(HostAndPort endpoint);

private:
    void initRequest(kms_request_t* request, StringData host);

private:
    // SSL Manager
    std::shared_ptr<SSLManagerInterface> _sslManager;

    // Server to connect to
    HostAndPort _server;

    // GCP configuration settings
    GCPConfig _config;

    // Service for managing oauth requests and token cache
    std::unique_ptr<GCPKMSOAuthService> _oauthService;
};

void GCPKMSService::initRequest(kms_request_t* request, StringData host) {
    // use current time
    uassertKmsRequest(kms_request_set_date(request, nullptr));

    // kms is always the name of the service
    uassertKmsRequest(kms_request_set_service(request, "kms"));

    // Set host to be the host we are targeting
    uassertKmsRequest(kms_request_add_header_field(request, "Host", host.toString().c_str()));
}

/**
 * Extracts key data from a "key ID" string
 */
BSONObj parseKMSKeyId(StringData kmsKeyId) {
    // kmsKeyID will be
    // projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
    // cryptoKeyVersions/VERSION is optional.
    BSONObjBuilder objBuilder;
    constexpr std::array<StringData, 5> fields = {
        kProjectIdField, kLocationIdField, kKeyRingField, kKeyNameField, kKeyVerisionField};

    // Tracks which token in kmsKeyId we are iterating over
    uint8_t iToken = 0;

    std::string idCopy = kmsKeyId.toString();
    std::stringstream ss(idCopy);
    std::string token;

    while (std::getline(ss, token, '/')) {
        if (iToken % 2 != 0) {
            uassert(5265001, "Malformed KMS Key ID for GCP", iToken < fields.size() * 2);
            objBuilder.append(fields[(iToken / 2)], token);
        }
        iToken++;
    }

    // Check that we have collected every field except for keyVersion, which is optional
    BSONObj obj = objBuilder.obj();
    for (size_t i = 0; i < fields.size() - 1; i++) {
        uassert(5256002, "Malformed KMS Key ID for GCP", obj.hasField(fields[i]));
    }

    return obj;
}

std::vector<uint8_t> GCPKMSService::encrypt(ConstDataRange cdr, StringData kmsKeyId) {
    StringData bearerToken = _oauthService->getBearerToken();
    BSONObj keyData = parseKMSKeyId(kmsKeyId);
    GcpMasterKey masterKey = GcpMasterKey::parse(IDLParserErrorContext("gcpMasterKey"), keyData);

    auto request = UniqueKmsRequest(kms_gcp_request_encrypt_new(
        _server.host().c_str(),
        bearerToken.toString().c_str(),
        masterKey.getProjectID().toString().c_str(),
        masterKey.getLocationID().toString().c_str(),
        masterKey.getKeyRing().toString().c_str(),
        masterKey.getKey().toString().c_str(),
        masterKey.getKeyVersion().has_value() ? masterKey.getKeyVersion().value().toString().c_str()
                                              : nullptr,
        reinterpret_cast<const uint8_t*>(cdr.data()),
        cdr.length(),
        _config.opts.get()));

    initRequest(request.get(), _server.host());

    auto buffer = UniqueKmsCharBuffer(kms_request_to_string(request.get()));
    auto buffer_len = strlen(buffer.get());

    KMSNetworkConnection connection(_sslManager.get());
    auto response = connection.makeOneRequest(_server, ConstDataRange(buffer.get(), buffer_len));

    auto body = kms_response_get_body(response.get(), nullptr);

    BSONObj obj = fromjson(body);

    if (obj.hasField("error")) {
        GcpKMSError gcpResponse;
        try {
            gcpResponse =
                GcpKMSError::parse(IDLParserErrorContext("gcpEncryptError"), obj["error"].Obj());
        } catch (DBException& dbe) {
            uasserted(5265005,
                      str::stream() << "GCP KMS failed to parse error message: " << dbe.toString()
                                    << ", Response : " << obj);
        }

        uasserted(5256006,
                  str::stream() << "GCP KMS failed to encrypt: " << gcpResponse.getCode() << " "
                                << gcpResponse.getStatus() << " : " << gcpResponse.getMessage());
    }

    auto gcpResponce = GcpEncryptResponse::parse(IDLParserErrorContext("gcpEncryptResponse"), obj);

    auto blobStr = base64::decode(gcpResponce.getCiphertext().toString());

    return kmsResponseToVector(blobStr);
}

SecureVector<uint8_t> GCPKMSService::decrypt(ConstDataRange cdr, BSONObj masterKey) {
    auto gcpMasterKey = GcpMasterKey::parse(IDLParserErrorContext("gcpMasterKey"), masterKey);
    StringData bearerToken = _oauthService->getBearerToken();

    auto request = UniqueKmsRequest(
        kms_gcp_request_decrypt_new(_server.host().c_str(),
                                    bearerToken.toString().c_str(),
                                    gcpMasterKey.getProjectID().toString().c_str(),
                                    gcpMasterKey.getLocationID().toString().c_str(),
                                    gcpMasterKey.getKeyRing().toString().c_str(),
                                    gcpMasterKey.getKey().toString().c_str(),
                                    reinterpret_cast<const uint8_t*>(cdr.data()),
                                    cdr.length(),
                                    _config.opts.get()));

    initRequest(request.get(), _server.host());

    auto buffer = UniqueKmsCharBuffer(kms_request_to_string(request.get()));
    auto buffer_len = strlen(buffer.get());
    KMSNetworkConnection connection(_sslManager.get());
    auto response = connection.makeOneRequest(_server, ConstDataRange(buffer.get(), buffer_len));

    auto body = kms_response_get_body(response.get(), nullptr);

    BSONObj obj = fromjson(body);

    if (obj.hasField("error")) {
        GcpKMSError gcpResponse;
        try {
            gcpResponse =
                GcpKMSError::parse(IDLParserErrorContext("gcpDecryptError"), obj["error"].Obj());
        } catch (DBException& dbe) {
            uasserted(5265007,
                      str::stream() << "GCP KMS failed to parse error message: " << dbe.toString()
                                    << ", Response : " << obj);
        }

        uasserted(5256008,
                  str::stream() << "GCP KMS failed to decrypt: " << gcpResponse.getCode() << " "
                                << gcpResponse.getStatus() << " : " << gcpResponse.getMessage());
    }

    auto gcpResponce = GcpDecryptResponse::parse(IDLParserErrorContext("gcpEncryptResponse"), obj);

    auto blobStr = base64::decode(gcpResponce.getPlaintext().toString());

    return kmsResponseToSecureVector(blobStr);
}

BSONObj GCPKMSService::encryptDataKey(ConstDataRange cdr, StringData keyId) {
    auto dataKey = encrypt(cdr, keyId);
    BSONObj keyData = parseKMSKeyId(keyId);

    GcpMasterKey masterKey = GcpMasterKey::parse(IDLParserErrorContext("gcpMasterKey"), keyData);

    GcpMasterKeyAndMaterial keyAndMaterial;
    keyAndMaterial.setKeyMaterial(dataKey);
    keyAndMaterial.setMasterKey(masterKey);

    return keyAndMaterial.toBSON();
}

std::unique_ptr<KMSService> GCPKMSService::create(const GcpKMS& config) {
    auto gcpKMS = std::make_unique<GCPKMSService>();

    SSLParams params;
    getSSLParamsForNetworkKMS(&params);

    // Leave the CA file empty so we default to system CA but for local testing allow it to inherit
    // the CA file.
    if (config.getEndpoint().has_value()) {
        params.sslCAFile = sslGlobalParams.sslCAFile;
    }
    gcpKMS->_server = parseUrl(config.getEndpoint().value_or(gcpKMSEndpoint));

    gcpKMS->_sslManager = SSLManagerInterface::create(params, false);

    gcpKMS->_config.email = config.getEmail().toString();

    gcpKMS->_config.opts = UniqueKmsRequestOpts(kms_request_opt_new());
    kms_request_opt_set_provider(gcpKMS->_config.opts.get(), KMS_REQUEST_PROVIDER_GCP);

    gcpKMS->configureOauthService(
        HostAndPort(config.getEndpoint().value_or(defaultOauthEndpoint).toString(), 443));

    gcpKMS->_config.privateKey = config.getPrivateKey().toString();

    return gcpKMS;
}

void GCPKMSService::configureOauthService(HostAndPort endpoint) {
    _oauthService = std::make_unique<GCPKMSOAuthService>(_config, endpoint, _sslManager);
}

/**
 * Factory for GCPKMSService if user specifies gcp config to mongo() JS constructor.
 */
class GCPKMSServiceFactory final : public KMSServiceFactory {
public:
    GCPKMSServiceFactory() = default;
    ~GCPKMSServiceFactory() = default;

    std::unique_ptr<KMSService> create(const BSONObj& config) final {
        auto field = config[KmsProviders::kGcpFieldName];
        if (field.eoo()) {
            return nullptr;
        }
        auto obj = field.Obj();
        return GCPKMSService::create(GcpKMS::parse(IDLParserErrorContext("root"), obj));
    }
};

}  // namespace

MONGO_INITIALIZER(KMSRegisterGCP)(::mongo::InitializerContext*) {
    kms_message_init();
    KMSServiceController::registerFactory(KMSProviderEnum::gcp,
                                          std::make_unique<GCPKMSServiceFactory>());
    return Status::OK();
}

}  // namespace mongo
