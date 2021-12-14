#pragma once

#include <napi.h>
#include <string>
#include <map>
#include <vector>
#include <windows.h>

class Provider
{
public:
	DWORD dwProvType;	// Legacy CSP type; 0 if provider is CNG
	std::string name;	// Enroll provider if isEnroll
};

class KeyWrap
{
public:
	boolean isEnroll;		// True if it wraps an enroll key
	Provider provider;		// Cryptographic provider
	std::string keyName;	// Windows key container or CNG key name if isEnroll

	std::string subject;	// Signing certificate subject, if !isEnroll
	std::string issuer;		// Signing certificate issuer, if !isEnroll
	std::string serial;		// Signing certificate serial number, encoded as hexadecimal, if !isEnroll

	KeyWrap(const std::string&, const DWORD, const std::string&);
	KeyWrap(const char*, const DWORD, const char*);
	KeyWrap(const std::string&, const std::string&, const std::string&);
	KeyWrap(const char*, const char*, const char*);
};

class KeyHandler
{
public:
	KeyHandler();
	~KeyHandler();

	int AddKey(const std::string&, const DWORD, const std::string&);
	int AddKey(const char*, const DWORD, const char*);
	int AddKey(const std::string&, const std::string&, const std::string&);
	int AddKey(const char*, const char*, const char*);
	void ReleaseKey(const int);
	void DeleteKey(const Napi::Env&, const int);
	KeyWrap* GetKey(const int);
	std::map<int, KeyWrap*>& GetHandlers();

private:
	int handlers;
	std::map<int, KeyWrap*> keys;
};


// Implements Hamahiri Node native module
class Hamahiri : public Napi::ObjectWrap<Hamahiri>
{
public:
	Hamahiri(const Napi::CallbackInfo&);

	Napi::Value EnumerateDevices(const Napi::CallbackInfo&);		// Implements enumerateDevices() member of Enroll
	Napi::Value GenerateKeyPair(const Napi::CallbackInfo&);			// Implements generateKeyPair() member of Enroll
	Napi::Value DeleteKeyPair(const Napi::CallbackInfo&);			// Implements deleteKeyPair() member of Enroll
	Napi::Value ReleaseKeyHandle(const Napi::CallbackInfo&);		// Implements releaseKeyHandle() member of Hamahiri
	Napi::Value Sign(const Napi::CallbackInfo&);					// Implements sign() member of Hamahiri
	Napi::Value InstallCertificate(const Napi::CallbackInfo&);		// Implements installCertificate() member of Enroll
	Napi::Value InstallChain(const Napi::CallbackInfo&);			// Implements installChain() member of Enroll
	Napi::Value EnumerateCertificates(const Napi::CallbackInfo&);	// Implements enumerateCertificates member of Sign

	static Napi::Function GetClass(Napi::Env);

private:
	KeyHandler handlers;
	std::vector<Provider> providers;

	void enumProviders(const Napi::Env&);
};

// Supported signing algorithms
enum SignMechanism
{
	CKM_SHA1_RSA_PKCS   = 0x00000006,
	CKM_SHA256_RSA_PKCS = 0x00000040,
	CKM_SHA384_RSA_PKCS = 0x00000041,
	CKM_SHA512_RSA_PKCS = 0x00000042
};

#define HH_KEY_CONTAINER					"Hamahiri key container "
#define HH_KEY_NAME							L"Hamahiri RSA key "

// Error codes
#define HH_SUCCESS							0L
#define HH_ARGUMENT_ERROR					1L
#define HH_UNSUPPORTED_MECHANISM_ERROR		2L
#define HH_INVALID_KEY_HANDLE				3L
#define HH_OUT_OF_MEM_ERROR					4L
#define HH_ENUM_PROV_ERROR					5L
#define HH_KEY_CONTAINER_ERROR				6L
#define HH_KEY_PAIR_GEN_ERROR				7L
#define HH_PUBKEY_EXPORT_ERROR				8L
#define HH_PUBKEY_ENCODING_ERROR			9L
#define HH_CNG_PROVIDER_ERROR				10L
#define HH_CNG_CREATE_KEY_ERROR				11L
#define HH_CNG_FINALIZE_KEY_ERROR			12L
#define HH_CAPI_CRETE_HASH_ERROR			13L
#define HH_CAPI_SET_HASH_ERROR				14L
#define HH_CAPI_SIGN_HASH_ERROR				15L
#define HH_CNG_SIGN_HASH_ERROR				16L
#define HH_CNG_OPEN_KEY_ERROR				17L
#define HH_CNG_DELETE_KEY_ERROR				18L
#define HH_CAPI_DELETE_KEY_ERROR			19L
#define HH_CAPI_OPEN_KEY_ERROR				20L
#define HH_CAPI_ENCODE_ERROR				21L
#define HH_CAPI_INIT_REQUEST_ERROR			22L
#define HH_CAPIT_SIGN_REQUEST_ERROR			23L