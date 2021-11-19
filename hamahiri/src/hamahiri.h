#pragma once

#include <napi.h>
#include <string>
#include <map>
#include <windows.h>

class KeyWrap
{
public:
	boolean     isKey;		// Windows handle to private key
	ULONG_PTR   hKey;		// Windows handle to private key if isKey; othwise NULL
	std::string keyName;	// Windows key container or key name if isKey
	DWORD       dwType;		// CSP type, if hKey is legacy; otherwise, 0;
	std::string provider;	// Windows CSP, if hKey is a CNG key

	std::string subject;	// Signing certificate subject, if !isKey
	std::string issuer;		// Signing certificate issuer, if !isKey
	std::string serial;		// Signing certificate serial number, encoded as hexadecimal, if !isKeys

	KeyWrap(const ULONG_PTR, const std::string&, const DWORD, const std::string&);
	KeyWrap(const std::string&, const std::string&, const std::string&);
	KeyWrap(const char*, const char*, const char*);
	~KeyWrap();
};
class KeyHandler
{
public:
	KeyHandler();
	~KeyHandler();

	int AddKey(const ULONG_PTR, const std::string&, const DWORD, const std::string&);
	int AddKey(const std::string&, const std::string&, const std::string&);
	int AddKey(const char*, const char*, const char*);
	void ReleaseKey(const int);
	void DeleteKey(const int);
	KeyWrap* GetKey(const int);
	std::map<int, KeyWrap*>& GetHandlers();

private:
	int __handlers;
	std::map<int, KeyWrap*> __keys;
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
	KeyHandler __handler;
	std::vector<std::string> __rsaProviders;
	std::vector<std::string> __aesProviders;
	std::vector<std::string> __CNGProviders;
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
#define HH_SUCCESS							0x0000000000000000L
#define HH_ARGUMENT_ERROR					0x0000000000000001L
#define HH_UNSUPPORTED_MECHANISM_ERROR		0x0000000000000002L
#define HH_INVALID_KEY_HANDLE				0x0000000000000003L
#define HH_OUT_OF_MEM_ERROR					0x0000000000000004L
#define HH_ENUM_PROV_ERROR					0x0000000000000005L
#define HH_KEY_CONTAINER_ERROR				0x0000000000000006L
#define HH_KEY_PAIR_GEN_ERROR				0x0000000000000007L
#define HH_PUBKEY_EXPORT_ERROR				0x0000000000000008L
#define HH_PUBKEY_ENCODING_ERROR			0x0000000000000009L
#define HH_CNG_PROVIDER_ERROR				0x000000000000000AL
#define HH_CNG_CREATE_KEY_ERROR				0x000000000000000BL
#define HH_CNG_FINALIZE_KEY_ERROR			0x000000000000000CL