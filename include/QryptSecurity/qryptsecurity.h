#ifndef QRYPTSECURITY_H
#define QRYPTSECURITY_H

#include <memory>
#include <string>
#include <vector>

namespace QryptSecurity {

const std::string QRYPTSECURITY_VERSION = "0.6";


/// <summary>
/// Enumeration of symmetric key modes
/// </summary>
enum class SymmetricKeyMode {
    /// <summary>
    /// AES-256
    /// </summary>
    SYMMETRIC_KEY_MODE_AES_256,

    /// <summary>
    /// OTP
    /// </summary>
    SYMMETRIC_KEY_MODE_OTP,

    /// <summary>
    /// Number of modes
    /// </summary>
    NUM_SYMMETRIC_KEY_MODES
};

/// <summary>
/// Structure to store symmetric key data
/// </summary>
struct SymmetricKeyData {

    /// <summary>
    /// Symmetric key
    /// </summary>
    std::vector<uint8_t> key;

    /// <summary>
    /// Symmetric key metadata
    /// </summary>
    std::vector<uint8_t> metadata;

};

/// <summary>
/// KeyGenDistributedClient
///
/// Use cases:
/// - Generate same symmetric keys for two devices (via BLAST API)
/// - Generate symmetric keys for single device (via BLAST API)
/// </summary>
class IKeyGenDistributedClient {
  public:

    IKeyGenDistributedClient(){};
    virtual ~IKeyGenDistributedClient(){};

    /// <summary>
    /// Factory function for creating objects
    /// </summary>
    ///
    /// <returns>An unique pointer to the constructed object</returns>
    static std::unique_ptr<IKeyGenDistributedClient> create();

    /// <summary>
    /// Initializes the client
    /// </summary>
    ///
    /// <param name="qryptToken">Qrypt token to access Qrypt services</param>
    virtual void initialize(std::string qryptToken) = 0;

    /// <summary>
    /// Initializes the client
    /// </summary>
    ///
    /// <param name="qryptToken">Qrypt token to access Qrypt services</param>
    /// <param name="caCertPath">Absolute path to a CA Root Certificate for use with libCurl</param>
    virtual void initialize(std::string qryptToken, std::string caCertPath) = 0;

    /// <summary>
    /// Generate symmetric key for this client and metadata for other client
    /// </summary>
    ///
    /// <param name="mode">Symmetric key algorithm</param>
    /// <returns>Symmetric key and metadata</returns>
    virtual SymmetricKeyData genInit(const SymmetricKeyMode mode) = 0;

    /// <summary>
    /// Generate symmetric key for this client and metadata for other client
    ///
    /// The input argument keySize is ignored for SYMMETRIC_KEY_MODE_AES_256 mode.
    /// </summary>
    ///
    /// <param name="mode">Symmetric key algorithm</param>
    /// <param name="keySize">Symmetric key size when using OTP mode</param>
    /// <returns>Symmetric key and metadata</returns>
    virtual SymmetricKeyData genInit(const SymmetricKeyMode mode, const size_t keySize) = 0;

    /// <summary>
    /// Generate symmetric key for this client from metadata
    /// </summary>
    ///
    /// <param name="metadata">Symmetric key metadata</param>
    /// <returns>Symmetric key</returns>
    virtual std::vector<uint8_t> genSync(std::vector<uint8_t> metadata) = 0;

};

} // namespace

#endif
