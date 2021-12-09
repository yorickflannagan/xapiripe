#include "hamahiri.h"
#include <ncrypt.h>

#include <fstream>

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
// Windows native functions
// * * * * * * * * * * * * * * *
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
	bSuccess = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncoded, &cbEncoded);
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
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded);
	LocalFree(pbEncoded);
	LocalFree(pInfo);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
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
	bSuccess = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncoded, &cbEncoded);
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
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded);

	LocalFree(pbEncoded);
	LocalFree(pInfo);
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
}

void cngSign(const Napi::Env env, const NCRYPT_KEY_HANDLE hKey, const uint32_t mechanism, BYTE* pbData, DWORD cbData, std::vector<uint8_t>& signature)
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
		return;
	}

	DWORD cbResult;
	BYTE* bSignature;
	SECURITY_STATUS stat = NCryptSignHash(hKey, &paddingInfo, pbData, cbData, NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not initialize hash signature", "cngSign", HH_CNG_SIGN_HASH_ERROR, stat);
		return;
	}
	bSignature = (BYTE*) LocalAlloc(LMEM_ZEROINIT, cbResult);
	if (!bSignature)
	{
		THROW_JS_ERROR(env, "Out of memory error", "cngSign", HH_OUT_OF_MEM_ERROR, GetLastError());
		return;
	}
	stat = NCryptSignHash(hKey, &paddingInfo, pbData, cbData, bSignature, cbResult, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
	if (stat == ERROR_SUCCESS)
	{
		signature.resize(cbResult);
		for (DWORD i = 0; i < cbResult; i++) signature[i] = bSignature[i];
	}
	else THROW_JS_ERROR(env, "Could not sign hash", "cngSign", HH_CNG_SIGN_HASH_ERROR, stat);
	LocalFree(bSignature);
}
void cngEnrollSign(const Napi::Env env, const std::wstring& provider, const std::wstring& keyName, const uint32_t mechanism, BYTE* pbData, DWORD cbData, std::vector<uint8_t>& signature)
{
	NCRYPT_PROV_HANDLE hProv;
	NCRYPT_KEY_HANDLE hKey;
	SECURITY_STATUS stat = NCryptOpenStorageProvider(&hProv, provider.c_str(), 0);
	if (stat != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Could not open CNG provider", "cngEnrollSign", HH_CNG_PROVIDER_ERROR, stat);
		return;
	}
	stat = NCryptOpenKey(hProv, &hKey, keyName.c_str(), AT_SIGNATURE, 0);
	if (stat != ERROR_SUCCESS)
	{
		NCryptFreeObject(hProv);
		THROW_JS_ERROR(env, "Could not open generated CNG private key", "cngEnrollSign", HH_CNG_OPEN_KEY_ERROR, stat);
		return;
	}
	cngSign(env, hKey, mechanism, pbData, cbData, signature);
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);
}
void capiSign(const Napi::Env env, const HCRYPTPROV hProv, const uint32_t mechanism, BYTE* pbData, std::vector<uint8_t>& signature)
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
		return;
	}

	HCRYPTHASH hHash;
	BOOL ret = CryptCreateHash(hProv, algID, NULL, 0, &hHash);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not create legacy hash object", "capiSign", HH_CAPI_CRETE_HASH_ERROR, GetLastError());
		return;
	}
	ret = CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not set legacy hash object", "capiSign", HH_CAPI_SET_HASH_ERROR, GetLastError());
		CryptDestroyHash(hHash);
		return;
	}
	BYTE* bSignature;
	DWORD cbResult;
	ret = CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &cbResult);
	if (!ret)
	{
		THROW_JS_ERROR(env, "Could not initialize legacy hash signature", "capiSign", HH_CAPI_SIGN_HASH_ERROR, GetLastError());
		CryptDestroyHash(hHash);
		return;
	}
	bSignature = (BYTE*) LocalAlloc(LMEM_ZEROINIT, cbResult);
	if (!bSignature)
	{
		THROW_JS_ERROR(env, "Out of memory error", "capiSign", HH_OUT_OF_MEM_ERROR, GetLastError());
		CryptDestroyHash(hHash);
		return;
	}
	ret = CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, bSignature, &cbResult);
	if (ret)
	{
		signature.resize(cbResult);
		for (DWORD i = 0; i < cbResult; i++) signature[i] = bSignature[i];
	}
	else THROW_JS_ERROR(env, "Could not sign legacy hash", "capiSign", HH_CAPI_SIGN_HASH_ERROR, GetLastError());
	LocalFree(bSignature);
	CryptDestroyHash(hHash);
}
void capiEnrollSign(const Napi::Env env, const std::string& provider, const DWORD dwProvType, const std::string& keyContainer, const uint32_t mechanism, BYTE* pbData, std::vector<uint8_t>& signature)
{
	HCRYPTPROV hProv;
	BOOL ret = CryptAcquireContextA(&hProv, keyContainer.c_str(), provider.c_str(), dwProvType, 0);
	DWORD dwError;
	if (!ret)
	{
		dwError = GetLastError();
		THROW_JS_ERROR(env, "Could not open legacy private key", "capiEnrollSign", HH_CAPI_OPEN_KEY_ERROR, GetLastError());
		return;
	}
	capiSign(env, hProv, mechanism, pbData, signature);
	CryptReleaseContext(hProv, 0);
}


// * * * * * * * * * * * * * * *
// Key/Certificates wrapper
// * * * * * * * * * * * * * * *
KeyWrap::KeyWrap(const std::string& provider, const DWORD dwType, const std::string& container)
{
	this->isEnroll = true;
	this->provider.dwProvType = dwType;
	this->provider.name.assign(provider);
	this->keyName.assign(container);
}
KeyWrap::KeyWrap(const char* szProvider, const DWORD dwType, const char* szContainer)
{
	this->isEnroll = true;
	this->provider.dwProvType = dwType;
	this->provider.name.assign(szProvider);
	this->keyName.assign(szContainer);
}
KeyWrap::KeyWrap(const std::string& subject, const std::string& issuer, const std::string& serial)
{
	this->isEnroll = false;
	this->subject.assign(subject);
	this->issuer.assign(issuer);
	this->serial.assign(serial);
}
KeyWrap::KeyWrap(const char* subject, const char* issuer, const char* serial)
{
	this->isEnroll = false;
	this->subject.assign(subject);
	this->issuer.assign(issuer);
	this->serial.assign(serial);
}

KeyHandler::KeyHandler()
{
	this->handlers = 0;
}
KeyHandler::~KeyHandler()
{
	for (std::map<int, KeyWrap*>::iterator it = this->keys.begin(); it != this->keys.end(); ++it) delete it->second;
}
int KeyHandler::AddKey(const std::string& provider, const DWORD dwType, const std::string& keyName)
{
	KeyWrap* key = new KeyWrap(provider, dwType, keyName);
	int hHandle = ++this->handlers;
	this->keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
int KeyHandler::AddKey(const char* szProvider, const DWORD dwType, const char* szContainer)
{
	KeyWrap* key = new KeyWrap(szProvider, dwType, szContainer);
	int hHandle = ++this->handlers;
	this->keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
int KeyHandler::AddKey(const std::string& subject, const std::string& issuer, const std::string& serial)
{
	KeyWrap* key = new KeyWrap(subject, issuer, serial);
	int hHandle = ++this->handlers;
	this->keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
int KeyHandler::AddKey(const char* subject, const char* issuer, const char* serial)
{
	KeyWrap* key = new KeyWrap(subject, issuer, serial);
	int hHandle = ++this->handlers;
	this->keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
void KeyHandler::ReleaseKey(const int hHandle)
{
	std::map<int, KeyWrap*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end())
	{
		delete it->second;
		this->keys.erase(hHandle);
	}
}
void KeyHandler::DeleteKey(const Napi::Env& env, const int hHandle)
{
	std::map<int, KeyWrap*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end())
	{
		if (it->second->isEnroll)
		{
			if (it->second->provider.dwProvType == 0)
			{
				std::wstring provider(it->second->provider.name.cbegin(), it->second->provider.name.cend());
				std::wstring keyName(it->second->keyName.cbegin(), it->second->keyName.cend());
				cngDeleteKey(env, provider, keyName);
			}
			else capiDeleteKey(env, it->second->provider.name, it->second->provider.dwProvType, it->second->keyName);
		}
		delete it->second;
		this->keys.erase(hHandle);
	}
}
KeyWrap* KeyHandler::GetKey(const int hHandle)
{
	KeyWrap* ret = NULL;
	std::map<int, KeyWrap*>::iterator it = this->keys.find(hHandle);
	if (it != this->keys.end()) ret = it->second;
	return ret;
}
std::map<int, KeyWrap*>& KeyHandler::GetHandlers()
{
	return this->keys;
}


// * * * * * * * * * * * * * * *
// The API itself
// * * * * * * * * * * * * * * *
Hamahiri::Hamahiri(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
	Napi::Env env = info.Env();
	// TODO: What else?
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

Napi::Value convert(const Napi::Env& env, const std::vector<uint8_t>& from)
{
	DWORD cbEncoded = from.size();
	BYTE* pbEncoded = (BYTE*) LocalAlloc(LMEM_ZEROINIT, cbEncoded);
	if (!pbEncoded)
	{
		THROW_JS_ERROR(env, "Out of memory error", "Hamahiri::convert", HH_OUT_OF_MEM_ERROR, GetLastError());
		return env.Null();
	}
	for (DWORD i = 0; i < cbEncoded; i++) pbEncoded[i] = from.at(i);
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded);
	LocalFree(pbEncoded);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
}
Napi::Value Hamahiri::GenerateKeyPair(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 2)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Wrong number of arguments"), "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
	}
    if (!info[0].IsString())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument device required"), "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
    }
	if (!info[1].IsNumber())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument keySize required"), "generateKeyPair", HH_ARGUMENT_ERROR);
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
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "The device argument does not correspond to an installed cryptographic device"), "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
	}

	int hHandle = 0;
	std::string keyContainer;
	Napi::Value retPubKey;
	if (dwProvType != 0) 
	{
		retPubKey = capiGenerateKeyPair(env, provider, dwProvType,  info[1].As<Napi::Number>().Int32Value(), keyContainer);
		if (env.IsExceptionPending()) return env.Null();
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
	hHandle = this->handlers.AddKey(provider, dwProvType, keyContainer);

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
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Wrong number of arguments"), "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument handle required"), "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	this->handlers.ReleaseKey(info[0].As<Napi::Number>().Int32Value());
	return Napi::Boolean::New(env, true);
}

Napi::Value Hamahiri::DeleteKeyPair(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Wrong number of arguments"), "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument handle required"), "releaseKeyHandle", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	this->handlers.DeleteKey(env, info[0].As<Napi::Number>().Int32Value());
	return Napi::Boolean::New(env, true);
}

Napi::Value Hamahiri::Sign(const Napi::CallbackInfo& info) 
{
	Napi::Env env = info.Env();
	if (info.Length() < 3)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Wrong number of arguments"), "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument hash must be Uint8Array"), "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[1].IsNumber())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument algorithm must be a number"), "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[2].IsNumber())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument key must be a number"), "sign", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::ArrayBuffer data = info[0].As<Napi::TypedArrayOf<uint8_t>>().ArrayBuffer();
	unsigned char* pbData = (unsigned char*) data.Data();
	DWORD cbData = data.ByteLength();
	uint32_t mechanism = info[1].As<Napi::Number>().Uint32Value();
	KeyWrap* wrapper = this->handlers.GetKey(info[2].As<Napi::Number>().Int32Value());
	if (!wrapper)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Invaid signing key handle"), "sign", HH_INVALID_KEY_HANDLE);
		return env.Null();
	}

	std::vector<uint8_t> signature;
	if (wrapper->isEnroll)
	{
		if (wrapper->provider.dwProvType == 0)
		{
			std::wstring cngProv(wrapper->provider.name.cbegin(), wrapper->provider.name.cend());
			std::wstring cngKey(wrapper->keyName.cbegin(), wrapper->keyName.cend());
			cngEnrollSign(env, cngProv, cngKey, mechanism, pbData, cbData, signature);
		}
		else capiEnrollSign(env, wrapper->provider.name, wrapper->provider.dwProvType, wrapper->keyName, mechanism, pbData, signature);
	}
	else
	{
		// TODO:
	}
	if (env.IsExceptionPending()) return env.Null();
	return convert(env, signature);
}

Napi::Value Hamahiri::InstallCertificate(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Wrong number of arguments"), "installCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsTypedArray())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument userCert must be an Uint8Array"), "installCertificate", HH_ARGUMENT_ERROR);
		return env.Null();
	}

	// TODO: Install user certificate using CryptoAPI
	return Napi::Boolean::New(env, true);
}

Napi::Value Hamahiri::InstallChain(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Wrong number of arguments"), "installChain", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	if (!info[0].IsArray())
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument chain must be an Array object"), "installChain", HH_ARGUMENT_ERROR);
		return env.Null();
	}
	Napi::Array arg = info[0].As<Napi::Array>();
	for (unsigned int i = 0; i < arg.Length(); i++)
	{
		if (!arg.Get(i).IsTypedArray())
		{
			THROW_JS_ERROR(env, Napi::TypeError::New(env, "Argument chain must be an array of Uint8Array"), "installChain", HH_ARGUMENT_ERROR);
			return env.Null();
		}
	}
	// TODO: Look for at least one user certificate signed by leaf CA of this chain
	// TODO: Check if chain is correct and ends in a self-signed certificate
	// TODO: Install chain
	return Napi::Boolean::New(env, true);
}

Napi::Value Hamahiri::EnumerateCertificates(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();

	// TODO: Enumerate signing certificates with CryptoAPI
	this->handlers.AddKey("CN = Francisvaldo Genevaldo das Torres 1601581365803", "CN = Common Name for All Cats End User CA, OU = PKI Ruler for All Cats, O = PKI Brazil, C = BR", "1A");

	std::map<int, KeyWrap*> keys = this->handlers.GetHandlers();
	std::vector<Napi::Object> certs;
	for (std::map<int, KeyWrap*>::iterator it = keys.begin(); it != keys.end(); ++it)
	{
		if (!it->second->isEnroll)
		{
			Napi::Object cert = Napi::Object::New(env);
			cert.Set("subject", it->second->subject);
			cert.Set("issuer", it->second->issuer);
			cert.Set("serial", it->second->serial);
			cert.Set("handle", it->first);
			certs.push_back(cert);
		}
	}
	Napi::Array ret = Napi::Array::New(env, certs.size());
	for (unsigned int i = 0; i < certs.size(); i++) ret[i] = certs.at(i);
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
		Hamahiri::InstanceMethod("sign",                  &Hamahiri::Sign),
		Hamahiri::InstanceMethod("installCertificate",    &Hamahiri::InstallCertificate),
		Hamahiri::InstanceMethod("installChain",          &Hamahiri::InstallChain),
		Hamahiri::InstanceMethod("enumerateCertificates", &Hamahiri::EnumerateCertificates)
	});
}


Napi::Object Init(Napi::Env env, Napi::Object exports)
{
	Napi::String name = Napi::String::New(env, "Hamahiri");
	exports.Set(name, Hamahiri::GetClass(env));
	return exports;
}
NODE_API_MODULE(addon, Init)
