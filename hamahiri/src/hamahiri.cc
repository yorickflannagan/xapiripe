#include "hamahiri.h"
#include <ncrypt.h>
#include <sstream>
#include <iomanip>

// * * * * * * * * * * * * * * *
// Javascript exception facility
// * * * * * * * * * * * * * * *
void THROW_JS_ERROR(Napi::Env env, Napi::Error& cause, char* method, unsigned long errorCode, unsigned long apiError)
{
	cause.Set("component", Napi::String::New(env, "Hamahiri"));
	cause.Set("method", Napi::String::New(env, method));
	cause.Set("errorCode", Napi::Number::New(env, errorCode));
	cause.Set("apiError", Napi::Number::New(env, apiError));
	cause.ThrowAsJavaScriptException();
}
void THROW_JS_ERROR(Napi::Env env, Napi::Error& cause, char* method, unsigned long errorCode)
{
	THROW_JS_ERROR(env, cause, method, errorCode, 0L);
}
void THROW_JS_ERROR(Napi::Env env, char* message, char* method, unsigned long errorCode, unsigned long apiError)
{
	Napi::Error err = Napi::Error::New(env, message);
	THROW_JS_ERROR(env, err, method, errorCode, apiError);
}
void THROW_JS_ERROR(Napi::Env env, char* message, char* method, unsigned long errorCode)
{
	THROW_JS_ERROR(env, message, method, errorCode, 0L);
}

// * * * * * * * * * * * * * * *
// Javascript ArrayBuffer free
// * * * * * * * * * * * * * * *
void cleanupHook(Napi::Env env, void* arg)
{
	LocalFree(arg);
}


// * * * * * * * * * * * * * * * * * *
// Enroll key and Certificate wrappers
// * * * * * * * * * * * * * * * * * *
EnrollKeyWrapper::EnrollKeyWrapper(const std::string& container, const DWORD dwType, const std::string& provider)
{
	this->keyName.assign(container);
	this->dwProvType = dwType;
	this->provider.assign(provider);
}
EnrollKeyHandler::EnrollKeyHandler()
{
	this->handlers = 0;
}
EnrollKeyHandler::~EnrollKeyHandler()
{
	for (std::map<int, EnrollKeyWrapper*>::iterator it = this->keys.begin(); it != this->keys.end(); ++it) delete it->second;
}
int EnrollKeyHandler::AddKey(const std::string& container, const DWORD dwType, const std::string& provider)
{
	EnrollKeyWrapper* key = new EnrollKeyWrapper(container, dwType, provider);
	int hHandle = ++this->handlers;
	this->keys.insert(std::pair<int, EnrollKeyWrapper*>(hHandle, key));
	return hHandle;
}
void EnrollKeyHandler::ReleaseKey(const int hHandle)
{
	std::map<int, EnrollKeyWrapper*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end())
	{
		delete it->second;
		this->keys.erase(hHandle);
	}
}
void cngDeleteKey(const Napi::Env env, const std::wstring& provider, const std::wstring& keyName)
{
	NCRYPT_PROV_HANDLE hProv;
	NCRYPT_KEY_HANDLE hKey;
	SECURITY_STATUS stat = NCryptOpenStorageProvider(&hProv, provider.c_str(), 0);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not open CNG provider", "cngDeleteKey", HH_CNG_PROVIDER_ERROR, stat);
		return;
	}
	stat = NCryptOpenKey(hProv, &hKey, keyName.c_str(), AT_SIGNATURE, 0);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not open CNG key container", "cngDeleteKey", HH_CNG_OPEN_KEY_ERROR, stat);
		NCryptFreeObject(hProv);
		return;
	}
	stat = NCryptDeleteKey(hKey, 0);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not delete CNG key", "cngDeleteKey", HH_CNG_DELETE_KEY_ERROR, stat);
		NCryptFreeObject(hKey);
		NCryptFreeObject(hProv);
		return;
	}
	NCryptFreeObject(hProv);
}
void capiDeleteKey(const Napi::Env env, const std::string& provider, const DWORD dwProvType, const std::string& keyContainer)
{
	HCRYPTPROV hProv;
	BOOL ret = CryptAcquireContextA(&hProv, keyContainer.c_str(), provider.c_str(), dwProvType, CRYPT_DELETEKEYSET);
	if (!ret) THROW_JS_ERROR(env, "Could not delete legacy key", "capiDeleteKey", HH_CAPI_DELETE_KEY_ERROR,  GetLastError());
}
void EnrollKeyHandler::DeleteKey(const Napi::Env& env, const int hHandle)
{
	std::map<int, EnrollKeyWrapper*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end())
	{
		if (it->second->dwProvType == 0)
		{
			std::wstring provider(it->second->provider.cbegin(), it->second->provider.cend());
			std::wstring keyName(it->second->keyName.cbegin(), it->second->keyName.cend());
			cngDeleteKey(env, provider, keyName);
		}
		else capiDeleteKey(env, it->second->provider, it->second->dwProvType, it->second->keyName);
		delete it->second;
		this->keys.erase(hHandle);
	}
}
EnrollKeyWrapper* EnrollKeyHandler::GetKey(const int hHandle)
{
	EnrollKeyWrapper* ret = NULL;
	std::map<int, EnrollKeyWrapper*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end()) ret = it->second;
	return ret;
}

CertificateWrapper::CertificateWrapper(const std::string& subject, const std::string& issuer, const std::string& serial, const std::vector<uint8_t>& encoded)
{
	this->subject.assign(subject);
	this->issuer.assign(issuer);
	this->serial.assign(serial);
	this->encoded.assign(encoded.cbegin(), encoded.cend());
}
CertificateHandler::CertificateHandler()
{
	this->handlers = 16384;
}
CertificateHandler::~CertificateHandler()
{
	for (std::map<int, CertificateWrapper*>::iterator it = this->keys.begin(); it != this->keys.end(); ++it) delete it->second;
}
int CertificateHandler::AddKey(const std::string& subject, const std::string& issuer, const std::string& serial, const std::vector<uint8_t>& encoded)
{
	CertificateWrapper* key = new CertificateWrapper(subject, issuer, serial, encoded);
	int hHandle = ++this->handlers;
	this->keys.insert(std::pair<int, CertificateWrapper*>(hHandle, key));
	return hHandle;
}
void CertificateHandler::Clear()
{
	this->keys.clear();
}
CertificateWrapper* CertificateHandler::GetKey(const int hHandle)
{
	CertificateWrapper* ret = NULL;
	std::map<int, CertificateWrapper*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end()) ret = it->second;
	return ret;
}


// * * * * * * * * * * * * * * *
// The API itself: Enroll
// * * * * * * * * * * * * * * *
Hamahiri::Hamahiri(const Napi::CallbackInfo& info) : ObjectWrap(info) {}

void cngEnumerateProviders(const Napi::Env env, std::vector<std::wstring>& list)
{
	DWORD dwCount = 0;
	NCryptProviderName* pProviderList = NULL;
	SECURITY_STATUS lRet = NCryptEnumStorageProviders(&dwCount, &pProviderList, 0);
	if (lRet != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Error enumerating CNG providers", "cngEnumerateProviders", HH_ENUM_PROV_ERROR, lRet);
		return;
	}
	list.resize(dwCount);
	for (DWORD i = 0; i < dwCount; i++)
	{
		std::wstring provName(pProviderList[i].pszName);
		list.push_back(provName);
	}
	NCryptFreeBuffer(pProviderList);
}
void capiEnumerateProviders(const Napi::Env env, const DWORD dwProvType, std::vector<std::string>& list)
{
	DWORD cbName, dwType, dwIndex = 0;
	while (CryptEnumProvidersA(dwIndex, NULL, 0, &dwType, NULL, &cbName))
	{
		if (dwType == dwProvType)
		{
			LPSTR pszName = (LPSTR) LocalAlloc(LMEM_ZEROINIT, cbName);
			if (!pszName)
			{
				THROW_JS_ERROR(env, "Out of memory", "capiEnumerateProviders", HH_OUT_OF_MEM_ERROR, GetLastError());
				return;
			}
			if (!(CryptEnumProvidersA(dwIndex, NULL, 0, &dwType, pszName, &cbName)))
			{
				THROW_JS_ERROR(env, "Error enumerating legacy providers", "capiEnumerateProviders", HH_ENUM_PROV_ERROR, GetLastError());
				LocalFree(pszName);
				return;
			}
			list.push_back(pszName);
			LocalFree(pszName);
		}
		dwIndex++;
	}
	DWORD dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_ITEMS)
		THROW_JS_ERROR(env, "Error enumerating legacy providers", "capiEnumerateProviders", HH_ENUM_PROV_ERROR, dwError);
}
void Hamahiri::enumProviders(const Napi::Env& env)
{
	std::vector<Provider> provs;
	std::vector<std::wstring> cng;
	cngEnumerateProviders(env, cng);
	if (env.IsExceptionPending()) return;
	for (size_t i = 0; i < cng.size(); i++)
	{
		std::string provName(cng.at(i).cbegin(), cng.at(i).cend());
		Provider prov;
		prov.dwProvType = 0;
		prov.name.assign(provName);
		provs.push_back(prov);
	}

	std::vector<std::string> legacy;
	capiEnumerateProviders(env, PROV_RSA_FULL, legacy);
	if (env.IsExceptionPending()) return;
	for (size_t i = 0; i < legacy.size(); i++)
	{
		Provider prov;
		prov.dwProvType = PROV_RSA_FULL;
		prov.name.assign(legacy.at(i));
		provs.push_back(prov);
	}

	legacy.clear();
	capiEnumerateProviders(env, PROV_RSA_AES, legacy);
	if (env.IsExceptionPending()) return;
	for (size_t i = 0; i < legacy.size(); i++)
	{
		Provider prov;
		prov.dwProvType = PROV_RSA_AES;
		prov.name.assign(legacy.at(i));
		provs.push_back(prov);
	}

	this->providers.clear();
	for (size_t i = 0; i < provs.size(); i++) if (!provs.at(i).name.empty()) this->providers.push_back(provs.at(i));
}
Napi::Value Hamahiri::EnumerateDevices(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	this->enumProviders(env);
	if (env.IsExceptionPending()) return env.Null();
	Napi::Array ret = Napi::Array::New(env, this->providers.size());
	for (size_t i = 0; i < this->providers.size(); i++) ret[i] = Napi::String::New(env, this->providers.at(i).name.c_str());
	return ret;
}

Napi::Value cngGenerateKeyPair(const Napi::Env& env, const std::wstring& provider, const DWORD ulKeyLen, std::wstring& keyName)
{
	NCRYPT_PROV_HANDLE hProv;
	SECURITY_STATUS stat = NCryptOpenStorageProvider(&hProv, provider.c_str(), 0);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not open specified CNG provider", "cngGenerateKeyPair", HH_CNG_PROVIDER_ERROR, stat);
		return env.Null();
	}
	WCHAR szName[1024], szNumber[32];
	NCRYPT_KEY_HANDLE hKey;
	int i = 0;
	bool bSuccess = false;
	while (!bSuccess)
	{
		_itow(i++, szNumber, 10);
		wcscpy(szName, HH_KEY_NAME);
		wcscat(szName, szNumber);
		stat = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, szName, AT_SIGNATURE, 0);
		if (!(bSuccess = stat == ERROR_SUCCESS) && stat != NTE_EXISTS)
		{
			NCryptFreeObject(hProv);
			THROW_JS_ERROR(env, "Could not create CNG persisted key", "cngGenerateKeyPair", HH_CNG_CREATE_KEY_ERROR, stat);
			return env.Null();
		}
	}

	DWORD dwExport = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, dwKeyUsage = NCRYPT_ALLOW_ALL_USAGES;
	NCRYPT_UI_POLICY pPolicy = { 1, NCRYPT_UI_PROTECT_KEY_FLAG | NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG, NULL, NULL, NULL };
	if
	(
		(stat = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE*)&dwExport, sizeof(DWORD), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (BYTE*)&dwKeyUsage, sizeof(DWORD), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (BYTE*)&ulKeyLen, sizeof(DWORD), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptSetProperty(hKey, NCRYPT_UI_POLICY_PROPERTY, (BYTE*)&pPolicy, sizeof(NCRYPT_UI_POLICY), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptFinalizeKey(hKey, 0)) != ERROR_SUCCESS
	)
	{
		NCryptDeleteKey(hKey, 0);
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Could generate CNG key pair", "cngGenerateKeyPair", HH_CNG_FINALIZE_KEY_ERROR, stat);
		return env.Null();
	}

	DWORD cbInfo, dwError;
	bSuccess = CryptExportPublicKeyInfo(hKey, AT_SIGNATURE, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, NULL, &cbInfo);
	if (!bSuccess)
	{
		dwError = GetLastError();
		NCryptDeleteKey(hKey, 0);
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Could not export RSA public key", "cngGenerateKeyPair", HH_PUBKEY_EXPORT_ERROR, dwError);
		return env.Null();
	}
	CERT_PUBLIC_KEY_INFO* pInfo = NULL;
	bSuccess = (pInfo = (CERT_PUBLIC_KEY_INFO*) LocalAlloc(LMEM_ZEROINIT, cbInfo)) ? TRUE : FALSE;
	if (!bSuccess)
	{
		dwError = GetLastError();
		NCryptDeleteKey(hKey, 0);
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Out of memory", "cngGenerateKeyPair", HH_OUT_OF_MEM_ERROR, dwError);
		return env.Null();
	}
	bSuccess = CryptExportPublicKeyInfo(hKey, AT_SIGNATURE, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, pInfo, &cbInfo);
	if (!bSuccess)
	{
		dwError = GetLastError();
		LocalFree(pInfo);
		NCryptDeleteKey(hKey, 0);
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Could not export RSA public key", "cngGenerateKeyPair", HH_PUBKEY_EXPORT_ERROR, dwError);
		return env.Null();
	}
	BYTE* pbEncoded;
	DWORD cbEncoded;
	bSuccess = CryptEncodeObjectEx(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncoded, &cbEncoded);
	if (!bSuccess)
	{
		dwError = GetLastError();
		LocalFree(pInfo);
		NCryptDeleteKey(hKey, 0);
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Could not DER encode RSA public key", "cngGenerateKeyPair", HH_PUBKEY_ENCODING_ERROR, dwError);
		return env.Null();
	}

	keyName.assign(szName);
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded, cleanupHook);
	LocalFree(pInfo);
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
}
Napi::Value capiGenerateKeyPair(const Napi::Env& env, std::string& provider, const DWORD dwType, const DWORD ulKeyLen, std::string& keyContainer)
{
	BOOL bSuccess = FALSE;
	int i = 0;
	CHAR szNumber[32], szContainer[1024];
	HCRYPTPROV hProv = NULL;
	DWORD dwError;

	while (!bSuccess)
	{
		_itoa(i++, szNumber, 10);
		strcpy(szContainer, HH_KEY_CONTAINER);
		strcat(szContainer, szNumber);
		bSuccess = CryptAcquireContextA(&hProv, szContainer, provider.c_str(), dwType, CRYPT_NEWKEYSET);
		if (!bSuccess)
		{
			dwError = GetLastError();
			if (dwError != NTE_EXISTS)
			{
				THROW_JS_ERROR(env, "Windows key container creation failure", "capiGenerateKeyPair", HH_KEY_CONTAINER_ERROR, dwError);
				return env.Null();
			}
		}
	}

	DWORD dwFlags = ((ulKeyLen << 16) | CRYPT_FORCE_KEY_PROTECTION_HIGH | CRYPT_USER_PROTECTED | CRYPT_EXPORTABLE);
	HCRYPTKEY hKey = NULL;
	bSuccess = CryptGenKey(hProv, AT_SIGNATURE, dwFlags, &hKey);
	if (!bSuccess)
	{
		dwError = GetLastError();
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, szContainer, provider.c_str(), dwType, CRYPT_DELETEKEYSET);
		THROW_JS_ERROR(env, "Key pair generation failure", "capiGenerateKeyPair", HH_KEY_PAIR_GEN_ERROR, dwError);
		return env.Null();
	}

	DWORD cbInfo;
	bSuccess = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, NULL, &cbInfo);
	if (!bSuccess)
	{
		dwError = GetLastError();
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, szContainer, provider.c_str(), dwType, CRYPT_DELETEKEYSET);
		THROW_JS_ERROR(env, "Public key export failure", "capiGenerateKeyPair", HH_PUBKEY_EXPORT_ERROR, dwError);
		return env.Null();
	}
	CERT_PUBLIC_KEY_INFO* pInfo = NULL;
	bSuccess = (pInfo = (CERT_PUBLIC_KEY_INFO*) LocalAlloc(LMEM_ZEROINIT, cbInfo)) ? TRUE : FALSE;
	if (!bSuccess)
	{
		dwError = GetLastError();
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, szContainer, provider.c_str(), dwType, CRYPT_DELETEKEYSET);
		THROW_JS_ERROR(env, "Out of memory error", "capiGenerateKeyPair", HH_OUT_OF_MEM_ERROR, dwError);
		return env.Null();
	}
	bSuccess = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, pInfo, &cbInfo);
	if (!bSuccess)
	{
		dwError = GetLastError();
		LocalFree(pInfo);
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, szContainer, provider.c_str(), dwType, CRYPT_DELETEKEYSET);
		THROW_JS_ERROR(env, "Public key export failure", "capiGenerateKeyPair", HH_PUBKEY_EXPORT_ERROR, dwError);
		return env.Null();
	}
	BYTE* pbEncoded;
	DWORD cbEncoded;
	bSuccess = CryptEncodeObjectEx(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncoded, &cbEncoded);
	if (!bSuccess)
	{
		dwError = GetLastError();
		LocalFree(pInfo);
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		CryptAcquireContextA(&hProv, szContainer, provider.c_str(), dwType, CRYPT_DELETEKEYSET);
		THROW_JS_ERROR(env, "Public key encoding failure", "capiGenerateKeyPair", HH_PUBKEY_ENCODING_ERROR, dwError);
		return env.Null();
	}

	keyContainer.assign(szContainer);
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded, cleanupHook);
	LocalFree(pInfo);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
}
Napi::Value Hamahiri::GenerateKeyPair(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 2)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
	}
    if (!info[0].IsString())
	{
		THROW_JS_ERROR(env, "Argument device required", "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
    }
	if (!info[1].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument keySize required", "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (this->providers.size() == 0) this->enumProviders(env);
	std::string provider = info[0].As<Napi::String>().Utf8Value();
	size_t i = 0;
	DWORD dwProvType = 0;
	bool bFound = false;
	while (!bFound && i < this->providers.size())
	{
		if ((bFound = this->providers.at(i).name.compare(provider) == 0)) dwProvType = this->providers.at(i).dwProvType;
		i++;
	}
	if (!bFound)
	{
		THROW_JS_ERROR(env, "The device argument does not correspond to an installed cryptographic device", "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
	}

	int hHandle = 0;
	std::string keyContainer;
	Napi::Value retPubKey;
	if (dwProvType != 0) 
	{
		retPubKey = capiGenerateKeyPair(env, provider, dwProvType, info[1].As<Napi::Number>().Int32Value(), keyContainer);
	}
	else
	{
		std::wstring cngProv(provider.cbegin(), provider.cend());
		std::wstring keyName;
		retPubKey = cngGenerateKeyPair(env, cngProv, info[1].As<Napi::Number>().Int32Value(), keyName);
		if (env.IsExceptionPending()) return env.Null();
		keyContainer.assign(keyName.cbegin(), keyName.cend());
	}
	if (env.IsExceptionPending()) return env.Null();
	hHandle = this->keyHandler.AddKey(keyContainer, dwProvType, provider);

	Napi::Object ret = Napi::Object::New(env);
	ret.Set("privKey", hHandle);
	ret.Set("pubKey", retPubKey.As<Napi::TypedArrayOf<uint8_t>>());
	return ret;
}

Napi::Value Hamahiri::ReleaseKeyHandle(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument handle required", "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	this->keyHandler.ReleaseKey(info[0].As<Napi::Number>().Int32Value());
	return Napi::Boolean::New(env, true);
}

Napi::Value Hamahiri::DeleteKeyPair(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument handle required", "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	this->keyHandler.DeleteKey(env, info[0].As<Napi::Number>().Int32Value());
	return Napi::Boolean::New(env, true);
}

Napi::Value cngSign(const Napi::Env env, const NCRYPT_KEY_HANDLE hKey, const uint32_t mechanism, BYTE* pbData, DWORD cbData)
{
	BCRYPT_PKCS1_PADDING_INFO paddingInfo = { NULL };
	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		paddingInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
		break;
	case CKM_SHA256_RSA_PKCS:
		paddingInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
		break;
	case CKM_SHA384_RSA_PKCS:
		paddingInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
		break;
	case CKM_SHA512_RSA_PKCS:
		paddingInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;
		break;
	default:
		THROW_JS_ERROR(env, "Unsupported signing algorithm", "cngSign", HH_UNSUPPORTED_MECHANISM_ERROR);
		return env.Null();
	}

	DWORD cbSignature;
	BYTE* pbSignature;
	SECURITY_STATUS stat = NCryptSignHash(hKey, &paddingInfo, pbData, cbData, NULL, 0, &cbSignature, NCRYPT_PAD_PKCS1_FLAG);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not initialize hash signature", "cngSign", HH_CNG_SIGN_HASH_ERROR, stat);
		return env.Null();
	}
	pbSignature = (BYTE*) LocalAlloc(LMEM_ZEROINIT, cbSignature);
	if (!pbSignature)
	{
		THROW_JS_ERROR(env, "Out of memory error", "cngSign", HH_OUT_OF_MEM_ERROR, GetLastError());
		return env.Null();
	}
	stat = NCryptSignHash(hKey, &paddingInfo, pbData, cbData, pbSignature, cbSignature, &cbSignature, NCRYPT_PAD_PKCS1_FLAG);
	if (stat != ERROR_SUCCESS)
	{
		LocalFree(pbSignature);
		THROW_JS_ERROR(env, "Could not sign hash", "cngSign", HH_CNG_SIGN_HASH_ERROR, stat);
		return env.Null();
	}
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbSignature, cbSignature, cleanupHook);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbSignature, buffer, 0, napi_uint8_array);
}
Napi::Value cngEnrollSign(const Napi::Env env, const std::wstring& provider, const std::wstring& keyName, const uint32_t mechanism, BYTE* pbData, DWORD cbData)
{
	NCRYPT_PROV_HANDLE hProv;
	NCRYPT_KEY_HANDLE hKey;
	SECURITY_STATUS stat = NCryptOpenStorageProvider(&hProv, provider.c_str(), 0);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not open CNG provider", "cngEnrollSign", HH_CNG_PROVIDER_ERROR, stat);
		return env.Null();
	}
	stat = NCryptOpenKey(hProv, &hKey, keyName.c_str(), AT_SIGNATURE, 0);
	if (stat != ERROR_SUCCESS)
	{
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Could not open generated CNG private key", "cngEnrollSign", HH_CNG_OPEN_KEY_ERROR, stat);
		return env.Null();
	}
	Napi::Value ret = cngSign(env, hKey, mechanism, pbData, cbData);
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);
	return ret;
}
Napi::Value capiSign(const Napi::Env env, const HCRYPTPROV hProv, const uint32_t mechanism, const BYTE* pbData, const DWORD cbData)
{
	ALG_ID algID;
	switch (mechanism)
	{
	case CKM_SHA1_RSA_PKCS:
		algID = CALG_SHA1;
		break;
	case CKM_SHA256_RSA_PKCS:
		algID = CALG_SHA_256;
		break;
	case CKM_SHA384_RSA_PKCS:
		algID = CALG_SHA_384;
		break;
	case CKM_SHA512_RSA_PKCS:
		algID = CALG_SHA_512;
		break;
	default:
		THROW_JS_ERROR(env, "Unsupported signing algorithm", "capiSign", HH_UNSUPPORTED_MECHANISM_ERROR);
		return env.Null();
	}

	HCRYPTHASH hHash = NULL;
	BOOL ret = CryptCreateHash(hProv, algID, NULL, 0, &hHash);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not create legacy hash object", "capiSign", HH_CAPI_CREATE_HASH_ERROR, GetLastError());
		return env.Null();
	}
	ret = CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not set legacy hash object", "capiSign", HH_CAPI_SET_HASH_ERROR, GetLastError());
		CryptDestroyHash(hHash);
		return env.Null();
	}
	BYTE* pbSignature;
	DWORD cbSignature;
	ret = CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &cbSignature);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not initialize legacy hash signature", "capiSign", HH_CAPI_SIGN_HASH_ERROR, GetLastError());
		CryptDestroyHash(hHash);
		return env.Null();
	}
	pbSignature = (BYTE*) LocalAlloc(LMEM_ZEROINIT, cbSignature);
	if (!pbSignature)
	{
		THROW_JS_ERROR(env, "Out of memory error", "capiSign", HH_OUT_OF_MEM_ERROR, GetLastError());
		CryptDestroyHash(hHash);
		return env.Null();
	}
	ret = CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &cbSignature);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not sign legacy hash", "capiSign", HH_CAPI_SIGN_HASH_ERROR, GetLastError());
		LocalFree(pbSignature);
		CryptDestroyHash(hHash);
		return env.Null();
	}

	register DWORD i = 0;
	register DWORD j = cbSignature - 1;
	BYTE temp;
	while (i < j)
	{
		temp = pbSignature[i];
		pbSignature[i] = pbSignature[j];
		pbSignature[j] = temp;
		i++, j--;
	}
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbSignature, cbSignature, cleanupHook);
	CryptDestroyHash(hHash);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbSignature, buffer, 0, napi_uint8_array);
}
Napi::Value capiEnrollSign(const Napi::Env env, const std::string& provider, const DWORD dwProvType, const std::string& keyContainer, const uint32_t mechanism, const BYTE* pbData, const DWORD cbData)
{
	HCRYPTPROV hProv = NULL;
	Napi::Value ret;
	if (CryptAcquireContextA(&hProv, keyContainer.c_str(), provider.c_str(), dwProvType, 0))
	{
		ret = capiSign(env, hProv, mechanism, pbData, cbData);
		CryptReleaseContext(hProv, 0);
	}
	else
	{
		THROW_JS_ERROR(env, "Could not open legacy private key", "capiEnrollSign", HH_CAPI_OPEN_KEY_ERROR, GetLastError());
		ret = env.Null();
	}
	return ret;
}
Napi::Value Hamahiri::SignRequest(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 3)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "signRequest", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, "Argument hash must be Uint8Array", "signRequest", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[1].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument algorithm must be a number", "signRequest", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[2].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument key must be a number", "signRequest", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::ArrayBuffer data = info[0].As<Napi::TypedArrayOf<uint8_t>>().ArrayBuffer();
	BYTE* pbData = (BYTE*) data.Data();
	DWORD cbData = data.ByteLength();
	uint32_t mechanism = info[1].As<Napi::Number>().Uint32Value();
	EnrollKeyWrapper* wrapper = this->keyHandler.GetKey(info[2].As<Napi::Number>().Int32Value());
	if (!wrapper)
	{
		THROW_JS_ERROR(env, "Invalid signing key handle", "sign", HH_INVALID_KEY_HANDLE);
		return env.Null();
	}

	Napi::Value ret;
	if (wrapper->dwProvType == 0)
	{
		std::wstring cngProv(wrapper->provider.cbegin(), wrapper->provider.cend());
		std::wstring cngKey(wrapper->keyName.cbegin(), wrapper->keyName.cend());
		ret = cngEnrollSign(env, cngProv, cngKey, mechanism, pbData, cbData);
	}
	else ret = capiEnrollSign(env, wrapper->provider, wrapper->dwProvType, wrapper->keyName, mechanism, pbData, cbData);
	if (env.IsExceptionPending()) return env.Null();
	return ret;
}

bool installCertificate(const Napi::Env& env, const BYTE* pbEncoded, DWORD cbEncoded)
{
	PCCERT_CONTEXT hCert;
	if (!(hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbEncoded, cbEncoded)))
	{
		THROW_JS_ERROR(env, "Could not create a certificate context to encoding", "installCertificate", HH_CERT_PARSING_ERROR, GetLastError());
		return env.Null();
	}
	if (!CryptFindCertificateKeyProvInfo(hCert, CRYPT_FIND_USER_KEYSET_FLAG, NULL))
	{
		THROW_JS_ERROR(env, "Could not find a private key corresponding to this certificate", "installCertificate", HH_CERT_PRIVKEY_FIND_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return env.Null();
	}

	CRYPT_KEY_PROV_INFO* phInfo;
	DWORD cbInfo;
	if (!CertGetCertificateContextProperty(hCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbInfo))
	{
		THROW_JS_ERROR(env, "Could not get certificate provider info", "installCertificate", HH_CERT_PROVIDER_FIND_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return env.Null();
	}
	if (!(phInfo = (CRYPT_KEY_PROV_INFO*) LocalAlloc(LMEM_ZEROINIT, cbInfo)))
	{
		THROW_JS_ERROR(env, "Out of memory error", "installCertificage", HH_OUT_OF_MEM_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return env.Null();
	}
	if (!CertGetCertificateContextProperty(hCert, CERT_KEY_PROV_INFO_PROP_ID, phInfo, &cbInfo))
	{
		THROW_JS_ERROR(env, "Could not get certificate provider info", "installCertificate", HH_CERT_PROVIDER_FIND_ERROR, GetLastError());
		LocalFree(phInfo);
		CertFreeCertificateContext(hCert);
		return env.Null();
	}
	CERT_KEY_CONTEXT hKey;
	NCRYPT_PROV_HANDLE hNProv = NULL;
	NCRYPT_KEY_HANDLE hNKey = NULL;
	HCRYPTPROV hProv = NULL;
	if (phInfo->dwProvType == 0)
	{
		SECURITY_STATUS stat;
		if ((stat = NCryptOpenStorageProvider(&hNProv, phInfo->pwszProvName, 0)) != ERROR_SUCCESS)
		{
			THROW_JS_ERROR(env, "Could no open CNG storage provider associated to specified certificate", "installCertificate", HH_CNG_PROVIDER_ERROR, stat);
			LocalFree(phInfo);
			CertFreeCertificateContext(hCert);
			return env.Null();
		}
		if ((stat = NCryptOpenKey(hNProv, &hNKey, phInfo->pwszContainerName, AT_SIGNATURE, 0)) != ERROR_SUCCESS)
		{
			THROW_JS_ERROR(env, "Could not get CNG private key associated to specified certificate", "installCertificate", HH_CNG_OPEN_KEY_ERROR, stat);
			NCryptFreeObject(hNProv);
			LocalFree(phInfo);
			CertFreeCertificateContext(hCert);
			return env.Null();
		}
		hKey.hCryptProv = hNKey;
		hKey.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
		hKey.cbSize = sizeof(hKey);
	}
	else
	{
		std::wstring wstring(phInfo->pwszContainerName);
		std::string keyContainer(wstring.cbegin(), wstring.cend());
		wstring.assign(phInfo->pwszProvName);
		std::string provider(wstring.cbegin(), wstring.cend());
		if (!CryptAcquireContextA(&hProv, keyContainer.c_str(), provider.c_str(), phInfo->dwProvType, 0))
		{
			THROW_JS_ERROR(env, "Could not open legacy private key associated to specified certificate", "installCertificate", HH_CAPI_OPEN_KEY_ERROR, GetLastError());
			LocalFree(phInfo);
			CertFreeCertificateContext(hCert);
			return env.Null();
		}
		hKey.hCryptProv = hProv;
		hKey.dwKeySpec = AT_SIGNATURE;
		hKey.cbSize = sizeof(hKey);

	}
	if (!CertSetCertificateContextProperty(hCert, CERT_KEY_CONTEXT_PROP_ID, 0, &hKey))
	{
		THROW_JS_ERROR(env, "Could not associate specified certificate to its private key", "installCertificate", HH_CERT_PRIVKEY_SET_ERROR, GetLastError());
		if (hNProv) NCryptFreeObject(hNProv);
		if (hNKey) NCryptFreeObject(hNKey);
		if (hProv) CryptReleaseContext(hProv, 0);
		LocalFree(phInfo);
		CertFreeCertificateContext(hCert);
		return env.Null();
	}
	if (hNProv) NCryptFreeObject(hNProv);
	if (hNKey) NCryptFreeObject(hNKey);
	if (hProv) CryptReleaseContext(hProv, 0);
	LocalFree(phInfo);

	HCERTSTORE hStore;
	if (!(hStore = CertOpenSystemStoreA(NULL, "MY")))	
	{
		THROW_JS_ERROR(env, "Could not open MY certificate store", "installCertificate", HH_CERT_STORE_OPEN_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return env.Null();
	}
	bool added = CertAddCertificateContextToStore(hStore, hCert, CERT_STORE_ADD_NEW, NULL);
	if (!added)
	{
		DWORD dwRet = GetLastError();
		if (dwRet != CRYPT_E_EXISTS ) THROW_JS_ERROR(env, "Could not add specified certificate to MY store", "installCertificate", HH_CERT_STORE_ADD_ERROR, dwRet);
	}
	CertCloseStore(hStore, 0);
	CertFreeCertificateContext(hCert);
	return added;
}
Napi::Value Hamahiri::InstallCertificate(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "installCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, "Argument userCert must be an Uint8Array", "installCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::ArrayBuffer data = info[0].As<Napi::TypedArrayOf<uint8_t>>().ArrayBuffer();
	BYTE* pbEncoded = (BYTE*) data.Data();
	DWORD cbEncoded = data.ByteLength();
	bool added = installCertificate(env, pbEncoded, cbEncoded);
	if (env.IsExceptionPending()) return env.Null();
	return Napi::Boolean::New(env, added);
}

bool installCACertificate(const Napi::Env& env, const BYTE* pbEncoded, const DWORD cbEncoded)
{
	PCCERT_CONTEXT hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbEncoded, cbEncoded);
	if (!hCert)
	{
		THROW_JS_ERROR(env, "Could not create a certificate context to encoding", "installCACertificate", HH_CERT_PARSING_ERROR, GetLastError());
		return false;
	}

	PCERT_EXTENSION pExt = hCert->pCertInfo->rgExtension;
	bool found = false;
	while (!found && pExt)
	{
		found = strcmp(pExt->pszObjId, "2.5.29.19") == 0;
		if (!found) pExt++;
	}
	if (!found)
	{
		THROW_JS_ERROR(env, "Could not find Basic Constraint certificate extension", "installCACertificate", HH_CA_CERT_EXT_ERROR);
		CertFreeCertificateContext(hCert);
		return false;
	}
	DWORD cbInfo;
	CERT_BASIC_CONSTRAINTS2_INFO* phInfo;
	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2, pExt->Value.pbData, pExt->Value.cbData, 0, NULL, &cbInfo))
	{
		THROW_JS_ERROR(env, "Could not decode Basic Constraint certificate extension", "installCACertificate", HH_DER_ENCONDING_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return false;
	}
	if (!(phInfo = (CERT_BASIC_CONSTRAINTS2_INFO*) LocalAlloc(LMEM_ZEROINIT, cbInfo)))
	{
		THROW_JS_ERROR(env, "Out of memory error", "installCACertificate", HH_OUT_OF_MEM_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return false;
	}
	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2, pExt->Value.pbData, pExt->Value.cbData, 0, phInfo, &cbInfo))
	{
		THROW_JS_ERROR(env, "Could not decode Basic Constraint certificate extension", "installCACertificate", HH_DER_ENCONDING_ERROR, GetLastError());
		LocalFree(phInfo);
		CertFreeCertificateContext(hCert);
		return false;
	}
	if (!phInfo->fCA)
	{
		THROW_JS_ERROR(env, "Certificate is not compliant with an RFC 5280 CA certificate", "installCACertificate", HH_CERT_NOT_CA_ERROR);
		LocalFree(phInfo);
		CertFreeCertificateContext(hCert);
		return false;
	}
	LocalFree(phInfo);
	bool isRoot = CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &hCert->pCertInfo->Issuer, &hCert->pCertInfo->Subject);

	HCERTSTORE hStore = CertOpenSystemStoreA(NULL, isRoot ? "Root" : "CA");
	if (!hStore)
	{
		THROW_JS_ERROR(env, "Could not open CA certificate store", "installCACertificate", HH_CERT_STORE_OPEN_ERROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return false;
	}
	bool added = CertAddCertificateContextToStore(hStore, hCert, CERT_STORE_ADD_NEW, NULL);
	if (!added)
	{
		DWORD dwRet = GetLastError();
		if (dwRet != CRYPT_E_EXISTS) THROW_JS_ERROR(env, "Could not add CA certificate to systema store", "installCACertificate", HH_CERT_STORE_ADD_ERROR, dwRet);
	}
	CertCloseStore(hStore, 0);
	CertFreeCertificateContext(hCert);
	return added;
}
Napi::Value Hamahiri::InstallCACertificate(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "installCACertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, "Argument userCert must be an Uint8Array", "installCACertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::ArrayBuffer data = info[0].As<Napi::TypedArrayOf<uint8_t>>().ArrayBuffer();
	BYTE* pbEncoded = (BYTE*) data.Data();
	DWORD cbEncoded = data.ByteLength();
	bool added = installCACertificate(env, pbEncoded, cbEncoded);
	if (env.IsExceptionPending()) return env.Null();
	return Napi::Boolean::New(env, added);
}

bool removeCertificate(const Napi::Env& env, const CHAR* szSubject, const CHAR* szIssuer, const CHAR* szSubsystem)
{
	HCERTSTORE hStore = CertOpenSystemStoreA(NULL, szSubsystem);
	if (!hStore)
	{
		THROW_JS_ERROR(env, "Could not open certificate store", "removeCertificate", HH_CERT_STORE_OPEN_ERROR, GetLastError());
		return false;
	}
	bool removed = false;
	PCCERT_CONTEXT pCtx = NULL;
	while ((pCtx = CertEnumCertificatesInStore(hStore, pCtx)))
	{
		CHAR szName[1024];
		DWORD cbName = sizeof(szName);
		CertGetNameStringA(pCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, cbName);
		if (strcmp(szSubject, szName) == 0)
		{
			CertGetNameStringA(pCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, cbName);
			if (strcmp(szIssuer, szName) == 0)
			{
				if (!CertDeleteCertificateFromStore(pCtx))
				{
					THROW_JS_ERROR(env, "Could not delete certificate from store", "removeCertificate", HH_CERT_DELETE_ERROR, GetLastError());
					CertFreeCertificateContext(pCtx);
					CertCloseStore(hStore, 0);
					return false;
				}
				pCtx = NULL;
				removed = true;
			}
		}
	}
	CertCloseStore(hStore, 0);
	return removed;
}
Napi::Value Hamahiri::DeleteCertificate(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 2)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "deleteCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsString())
	{
		THROW_JS_ERROR(env, "Argument subject must be a string", "deleteCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[1].IsString())
	{
		THROW_JS_ERROR(env, "Argument issuer must be a string", "deleteCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	std::string szSubject = info[0].As<Napi::String>().Utf8Value();
	std::string szIssuer = info[1].As<Napi::String>().Utf8Value();

	CHAR* szSubystem[] = { "MY", "CA", "Root" };
	bool removed = false;
	int i = 0;
	while (!removed && i < 2)
	{
		removed = removeCertificate(env, szSubject.c_str(), szIssuer.c_str(), szSubystem[i]);
		if (env.IsExceptionPending()) return env.Null();
		i++;
	}
	return Napi::Boolean::New(env, removed);
}



// * * * * * * * * * * * * * * *
// The API itself: Sign
// * * * * * * * * * * * * * * *
void enumCerts(const Napi::Env& env, std::vector<Certificate>& out)
{
	HCERTSTORE hStore = CertOpenSystemStoreA(NULL, "MY");
	if (!hStore)
	{
		THROW_JS_ERROR(env, "Could not open certificate store", "enumCerts", HH_CERT_STORE_OPEN_ERROR, GetLastError());
		return;
	}
	PCCERT_CONTEXT hCert = NULL;
	while ((hCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, hCert)))
	{
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey;
		DWORD dwKeySpec;
		BOOL mustFree;
		if
		(
			!CertVerifyTimeValidity(NULL, hCert->pCertInfo) &&
			CryptAcquireCertificatePrivateKey(hCert, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &hKey, &dwKeySpec, &mustFree)
		)
		{
			if (mustFree)
			{
				if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(hKey);
				else CryptReleaseContext(hKey, 0);
			}

			CHAR szName[1024];
			DWORD cbName = sizeof(szName);
			CertGetNameStringA(hCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, cbName);
			std::string subject(szName);
			CertGetNameStringA(hCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, cbName);
			std::string issuer(szName);
			std::stringbuf buffer;
			std::ostream os(&buffer);
			DWORD i;
			os << std::setfill('0');
			for (i = 0; i < hCert->pCertInfo->SerialNumber.cbData; i++)
			{
				os << std::hex << std::setw(2) << (int) hCert->pCertInfo->SerialNumber.pbData[i];
			}
			std::string serial = buffer.str();
			std::vector<uint8_t> encoded(hCert->cbCertEncoded, 0);
			for (i = 0; i < hCert->cbCertEncoded; i++) encoded[i] = hCert->pbCertEncoded[i];
			Certificate cert;
			cert.subject.assign(subject);
			cert.issuer.assign(issuer);
			cert.serial.assign(serial);
			cert.encoded.assign(encoded.cbegin(), encoded.cend());
			out.push_back(cert);
		}
	}
	CertCloseStore(hStore, 0);
}
Napi::Value Hamahiri::EnumerateCertificates(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	std::vector<Certificate> certs;
	enumCerts(env, certs);
	if (env.IsExceptionPending()) return env.Null();
	this->certHandler.Clear();
	std::vector<Napi::Object> certsJS;
	for (std::vector<Certificate>::iterator it = certs.begin(); it != certs.end(); ++it)
	{
		int hHandle = this->certHandler.AddKey(it->subject, it->issuer, it->serial, it->encoded);
		Napi::Object cert = Napi::Object::New(env);
		cert.Set("subject", it->subject);
		cert.Set("issuer", it->issuer);
		cert.Set("serial", it->serial);
		cert.Set("handle", hHandle);
		certsJS.push_back(cert);
	}
	Napi::Array ret = Napi::Array::New(env, certsJS.size());
	for (unsigned int i = 0; i < certsJS.size(); i++) ret[i] = certsJS.at(i);
	return ret;
}

Napi::Value sign(const Napi::Env env, const BYTE* pbEncoded, const DWORD cbEncoded, const uint32_t mechanism, BYTE* pbData, DWORD cbData)
{
	PCCERT_CONTEXT hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbEncoded, cbEncoded);
	if (!hCert)
	{
		THROW_JS_ERROR(env, "Could not create a certificate context to encoding", "sign", HH_CERT_PARSING_ERROR, GetLastError());
		return env.Null();
	}
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey;
	DWORD dwKeySpec;
	BOOL mustFree;
	if (!CryptAcquireCertificatePrivateKey(hCert, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &hKey, &dwKeySpec, &mustFree))
	{
		THROW_JS_ERROR(env, "Could not acquire key from certificate context", "sign", HH_ACQUIRE_KEY_ERRROR, GetLastError());
		CertFreeCertificateContext(hCert);
		return env.Null();
	}
	Napi::Value ret;
	if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) ret = cngSign(env, hKey, mechanism, pbData, cbData);
	else ret = capiSign(env, hKey, mechanism, pbData, cbData);
	if (mustFree)
	{
		if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(hKey);
		else CryptReleaseContext(hKey, 0);
	}
	CertFreeCertificateContext(hCert);
	return ret;
}
Napi::Value Hamahiri::Sign(const Napi::CallbackInfo& info) 
{
	Napi::Env env = info.Env();
	if (info.Length() < 3)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, "Argument hash must be Uint8Array", "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[1].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument algorithm must be a number", "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[2].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument key must be a number", "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::ArrayBuffer data = info[0].As<Napi::TypedArrayOf<uint8_t>>().ArrayBuffer();
	BYTE* pbData = (BYTE*) data.Data();
	DWORD cbData = data.ByteLength();
	uint32_t mechanism = info[1].As<Napi::Number>().Uint32Value();
	CertificateWrapper* wrapper = this->certHandler.GetKey(info[2].As<Napi::Number>().Int32Value());
	if (!wrapper)
	{
		THROW_JS_ERROR(env, "Invalid signing key handle", "sign", HH_INVALID_KEY_HANDLE);
		return env.Null();
	}

	Napi::Value ret = sign(env, wrapper->encoded.data(), wrapper->encoded.size(), mechanism, pbData, cbData);
	if (env.IsExceptionPending()) return env.Null();
	return ret;
}

void getChain(const Napi::Env& env, const BYTE* pbEncoded, const DWORD cbEncoded, std::vector<std::vector<uint8_t>>& out)
{
	PCCERT_CONTEXT hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbEncoded, cbEncoded);
	if (!hCert)
	{
		THROW_JS_ERROR(env, "Could not create a certificate context to encoding", "getChain", HH_CERT_PARSING_ERROR, GetLastError());
		return;
	}
	CERT_ENHKEY_USAGE enhkeyUsage = { 0, NULL };
	CERT_USAGE_MATCH certUsage = { USAGE_MATCH_TYPE_AND, enhkeyUsage };
	CERT_CHAIN_PARA params = { sizeof(CERT_CHAIN_PARA), certUsage };
	PCCERT_CHAIN_CONTEXT pChain;
	if (!CertGetCertificateChain(NULL, hCert, NULL, NULL, &params, 0, NULL, &pChain))
	{
		CertFreeCertificateContext(hCert);
		return;
	}
	for (DWORD i = 0; i < pChain->rgpChain[0]->cElement; i++)
	{
		DWORD cbSize = pChain->rgpChain[0]->rgpElement[i]->pCertContext->cbCertEncoded;
		std::vector<uint8_t> encoded(cbSize, 0);
		for (DWORD j = 0; j < cbSize; j++) encoded[j] = pChain->rgpChain[0]->rgpElement[i]->pCertContext->pbCertEncoded[j];
		out.push_back(encoded);
	}
	CertFreeCertificateChain(pChain);
	CertFreeCertificateContext(hCert);
}
Napi::Value Hamahiri::GetCertificateChain(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "getCertificateChain", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		THROW_JS_ERROR(env, "Argument handle must be a Number", "getCertificateChain", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	CertificateWrapper* wrapper = this->certHandler.GetKey(info[0].As<Napi::Number>().Int32Value());
	if (!wrapper)
	{
		THROW_JS_ERROR(env, "Invaid signing certificate handle", "getCertificateChain", HH_INVALID_KEY_HANDLE);
		return env.Null();
	}

	std::vector<std::vector<uint8_t>> chain;
	getChain(env, wrapper->encoded.data(), wrapper->encoded.size(), chain);
	if (env.IsExceptionPending()) return env.Null();
	Napi::Array ret = Napi::Array::New(env, chain.size());
	for (size_t i = 0; i < chain.size(); i++)
	{
		BYTE* pbEncoded = (BYTE*) LocalAlloc(LMEM_ZEROINIT, chain[i]. size());
		if (!pbEncoded)
		{
			THROW_JS_ERROR(env, "Out of memory error", "getCertificateChain", HH_OUT_OF_MEM_ERROR, GetLastError());
			return env.Null();
		}
		memcpy(pbEncoded, chain[i].data(), chain[i].size());
		Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, chain[i].size(), cleanupHook);
		ret[i] = Napi::TypedArrayOf<uint8_t>::New(env, chain[i].size(), buffer, 0, napi_uint8_array);
	}
	return ret;
}

void searchIssuerInStore(const Napi::Env& env, PCCERT_CONTEXT hCert, LPCSTR szStore, std::vector<std::vector<uint8_t>>& out)
{
	HCERTSTORE hStore;
	if (!(hStore = CertOpenSystemStoreA(NULL, szStore)))	
	{
		THROW_JS_ERROR(env, "Could not open certificate store", "searchIssuerInStore", HH_CERT_STORE_OPEN_ERROR, GetLastError());
		return;
	}
	PCCERT_CONTEXT hIssuer = NULL;
	while ((hIssuer = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, hCert, hIssuer)))
	{
		DWORD cbSize = hIssuer->cbCertEncoded;
		std::vector<uint8_t> encoded(cbSize, 0);
		for (DWORD i = 0; i < cbSize; i++) encoded[i] = hIssuer->pbCertEncoded[i];
		out.push_back(encoded);
	}
	CertCloseStore(hStore, 0);
}
void findIssuerOf(const Napi::Env& env, const BYTE* pbEncoded, DWORD cbEncoded, std::vector<std::vector<uint8_t>>& out)
{
	PCCERT_CONTEXT hCert;
	if (!(hCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbEncoded, cbEncoded)))
	{
		THROW_JS_ERROR(env, "Could not create a certificate context to encoding", "findIssuerOf", HH_CERT_PARSING_ERROR, GetLastError());
		return;
	}
	searchIssuerInStore(env, hCert, "CA", out);
	if (env.IsExceptionPending())
	{
		CertFreeCertificateContext(hCert);
		return;
	}
	searchIssuerInStore(env, hCert, "Root", out);
	CertFreeCertificateContext(hCert);
}
Napi::Value Hamahiri::GetIssuerOf(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, "Wrong number of arguments", "getIssuerOf", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, "Argument cert must be an Uint8Array", "getIssuerOf", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::ArrayBuffer data = info[0].As<Napi::TypedArrayOf<uint8_t>>().ArrayBuffer();
	BYTE* pbEncoded = (BYTE*) data.Data();
	DWORD cbEncoded = data.ByteLength();

	std::vector<std::vector<uint8_t>> issuers;
	findIssuerOf(env, pbEncoded, cbEncoded, issuers);
	if (env.IsExceptionPending()) return env.Null();
	Napi::Array ret = Napi::Array::New(env, issuers.size());
	for (size_t i = 0; i < issuers.size(); i++)
	{
		BYTE* pbEncodedIssuer = (BYTE*) LocalAlloc(LMEM_ZEROINIT, issuers[i]. size());
		if (!pbEncodedIssuer)
		{
			THROW_JS_ERROR(env, "Out of memory error", "getIssuerOf", HH_OUT_OF_MEM_ERROR, GetLastError());
			return env.Null();
		}
		memcpy(pbEncodedIssuer, issuers[i].data(), issuers[i].size());
		Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncodedIssuer, issuers[i].size(), cleanupHook);
		ret[i] = Napi::TypedArrayOf<uint8_t>::New(env, issuers[i].size(), buffer, 0, napi_uint8_array);
	}
	return ret;
}

Napi::Function Hamahiri::GetClass(Napi::Env env)
{
	return DefineClass(env, "Hamahiri",
	{
		Hamahiri::InstanceMethod("enumerateDevices",      &Hamahiri::EnumerateDevices),
		Hamahiri::InstanceMethod("generateKeyPair",       &Hamahiri::GenerateKeyPair),
		Hamahiri::InstanceMethod("releaseKeyHandle",      &Hamahiri::ReleaseKeyHandle),
		Hamahiri::InstanceMethod("deleteKeyPair",         &Hamahiri::DeleteKeyPair),
		Hamahiri::InstanceMethod("signRequest",           &Hamahiri::SignRequest),
		Hamahiri::InstanceMethod("installCertificate",    &Hamahiri::InstallCertificate),
		Hamahiri::InstanceMethod("installCACertificate",  &Hamahiri::InstallCACertificate),
		Hamahiri::InstanceMethod("deleteCertificate",     &Hamahiri::DeleteCertificate),

		Hamahiri::InstanceMethod("enumerateCertificates", &Hamahiri::EnumerateCertificates),
		Hamahiri::InstanceMethod("sign",                  &Hamahiri::Sign),
		Hamahiri::InstanceMethod("getCertificateChain",   &Hamahiri::GetCertificateChain),
		Hamahiri::InstanceMethod("getIssuerOf",           &Hamahiri::GetIssuerOf)
	});
}


Napi::Object Init(Napi::Env env, Napi::Object exports)
{
	Napi::String name = Napi::String::New(env, "Hamahiri");
	exports.Set(name, Hamahiri::GetClass(env));
	return exports;
}
NODE_API_MODULE(addon, Init)
