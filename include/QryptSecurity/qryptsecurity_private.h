#ifndef QRYPTSECURITY_PRIVATE_H
#define QRYPTSECURITY_PRIVATE_H

#include "qryptsecurity.h"

namespace QryptSecurity {

/// <summary>
/// Enumeration of cloud environments
/// </summary>
enum class FQDN_ENV {
    /// <summary>
    /// Production environment
    /// </summary>
    FQDN_ENV_PROD,

    /// <summary>
    /// Staging environment
    /// </summary>
    FQDN_ENV_STAGING,

    /// <summary>
    /// Development environment
    /// </summary>
    FQDN_ENV_DEV,

    /// <summary>
    /// Local environment
    /// </summary>
    FQDN_ENV_LOCAL,

    /// <summary>
    /// Number of cloud environments
    /// </summary>
    NUM_FQDN_ENV
};

/// <summary>
/// Set RPS cloud environment
/// </summary>
///
/// <param name="env">Cloud environment</param>
void setRpsEnv(FQDN_ENV env);

/// <summary>
/// Set BLAST cloud environment
/// </summary>
///
/// <param name="env">Cloud environment</param>
void setBlastEnv(FQDN_ENV env);

// ----------------------------------------------------
// IKeyGenLocalClient will be hidden from customers
// until there is a need. This will reduce maintenance
// effort on the engineering team.
// ----------------------------------------------------

/// <summary>
/// Structure to store random location configurations
/// </summary>
struct LocationConfig {

    /// <summary>
    /// Unique identifier for the location
    /// </summary>
    std::string id;

    /// <summary>
    /// Absolute or relative path to the location
    /// </summary>
    std::string path;

    /// <summary>
    /// Maximum space to be used for downloaded random
    /// </summary>
    size_t availableSize;

    /// <summary>
    /// Equality operator
    /// </summary>
    bool operator==(const LocationConfig& rhs) const;
};

/// <summary>
/// Structure to store local random cache configurations
/// </summary>
struct CacheConfig {

    /// <summary>
    /// Device secret is the password to unlock local on-disk database
    /// </summary>
    std::vector<uint8_t> deviceSecret;

    /// <summary>
    /// List of locations to save downloaded random
    /// </summary>
    std::vector<LocationConfig> locations;

    /// <summary>
    /// Maximum number of usable random cached bytes within a maintenance interval
    /// </summary>
    size_t maxNumCachedBytes;

    /// <summary>
    /// Minimum number of usable random cached bytes within a maintenance interval
    /// </summary>
    size_t minNumCachedBytes;

    /// <summary>
    /// Time (in seconds) between random download attempts
    /// </summary>
    size_t maintenanceInterval;

};

/// <summary>
/// Enumeration of asymmetric key modes
/// </summary>
enum class AsymmetricKeyMode {
    /// <summary>
    /// Elliptic-curve Diffie-Hellman 
    /// </summary>
    ASYMMETRIC_KEY_MODE_ECDH,

    /// <summary>
    /// FrodoKEM
    /// </summary>
    ASYMMETRIC_KEY_MODE_FRODO,

    /// <summary>
    /// Kyber Crystals
    /// </summary>
    ASYMMETRIC_KEY_MODE_KYBER,

    /// <summary>
    /// Number of modes
    /// </summary>
    NUM_ASYMMETRIC_KEY_MODES
};

/// <summary>
/// Structure to store asymmetric keys
/// </summary>
struct AsymmetricKeyPair {

    /// <summary>
    /// Private key
    /// </summary>
    std::vector<uint8_t> privateKey;

    /// <summary>
    /// Public key
    /// </summary>
    std::vector<uint8_t> publicKey;

};

/// <summary>
/// Enumeration of cache state
/// </summary>
enum class CacheState {
    /// <summary>
    /// Downloading initial random pool
    /// </summary>
    CACHE_STATE_DOWNLOADING,

    /// <summary>
    /// Initial local random pool created
    /// </summary>
    CACHE_STATE_READY,

    /// <summary>
    /// Number of cache states
    /// </summary>
    NUM_CACHE_STATES
};

/// <summary>
/// Structure for cache status information
/// </summary>
struct CacheStatus {

    /// <summary>
    /// Cache state
    /// </summary>
    CacheState state;

    /// <summary>
    /// Remaining usable cached random bytes
    /// </summary>
    uint64_t remainingCapacity;

    /// <summary>
    /// Total downloaded random to disk
    /// </summary>
    uint64_t totalDownloadedRandom;

};

/// <summary>
/// KeyGenLocalClient
///
/// Use cases:
/// - Generate symmetric keys for single device (via entropy API and local BLAST)
/// - Generate asymmetric keys for single device (via entropy API and local BLAST)
/// - Rapidly generate symmetric or asymmetric keys for single device
///
/// Notes:
/// - This class will store state on disk
/// - Used random pools will automatically be deleted
/// </summary>
class IKeyGenLocalClient {
  public:

    IKeyGenLocalClient(){};
    virtual ~IKeyGenLocalClient(){};

    /// <summary>
    /// Factory function for creating objects
    /// </summary>
    ///
    /// <returns>An unique pointer to the constructed object</returns>
    static std::unique_ptr<IKeyGenLocalClient> create();

    /// <summary>
    /// Initializes the client
    ///
    /// A background thread will be spawned that will be responsible for maintenace 
    /// operations such as downloading more random.
    /// </summary>
    ///
    /// <param name="qryptToken">Qrypt token to access Qrypt services</param>
    /// <param name="config">Cache configuration</param>
    virtual void initializeAsync(std::string qryptToken, CacheConfig config) = 0;

    /// <summary>
    /// Updates device secret used by client
    /// </summary>
    ///
    /// <param name="deviceSecret">The current device secret</param>
    /// <param name="newDeviceSecret">The new device secret</param>
    virtual void updateDeviceSecret(std::vector<uint8_t> deviceSecret, std::vector<uint8_t> newDeviceSecret) = 0;

    /// <summary>
    /// Deletes random and associated metadata from all locations
    /// </summary>
    virtual void wipe() = 0;

    /// <summary>
    /// Returns the current state of the cache and checks for potential errors
    /// </summary>
    ///
    /// <returns>Download status</returns>
    virtual CacheStatus checkCacheStatus() = 0;

    /// <summary>
    /// Generate asymmetric keys
    /// </summary>
    ///
    /// <param name="mode">Asymmetric key algorithm</param>
    /// <returns>Asymmetric key</returns>
    virtual AsymmetricKeyPair genAsymmetricKeys(AsymmetricKeyMode mode) = 0;

    /// <summary>
    /// Generate symmetric keys
    /// </summary>
    ///
    /// <param name="mode">Symmetric key algorithm</param>
    /// <returns>Symmetric key</returns>
    virtual std::vector<uint8_t> genSymmetricKey(SymmetricKeyMode mode) = 0;

    /// <summary>
    /// Generate symmetric keys
    ///
    /// The input argument keySize is ignored for SYMMETRIC_KEY_MODE_AES_256 mode.
    /// </summary>
    ///
    /// <param name="mode">Symmetric key algorithm</param>
    /// <param name="keySize">Symmetric key size when using OTP mode</param>
    /// <returns>Symmetric key</returns>
    virtual std::vector<uint8_t> genSymmetricKey(SymmetricKeyMode mode, size_t keySize) = 0;

};

} // namespace

#endif
