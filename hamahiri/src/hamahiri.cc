#include "hamahiri.h"
#include <ncrypt.h>

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
void capiEnumerateProviders(const Napi::Env env, const DWORD dwProvType, std::vector<std::string>& out)
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
			out.push_back(pszName);
			LocalFree(pszName);
		}
		dwIndex++;
	}
	DWORD dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_ITEMS) THROW_JS_ERROR(env, "Error enumerating legacy providers", "capiEnumerateProviders", HH_ENUM_PROV_ERROR, dwError);
}
void cngEnumerateProviders(const Napi::Env env, std::vector<std::string>& out)
{
	DWORD dwCount = 0, i = 0;
	NCryptProviderName *pProviderList = NULL;
	bool bOK = true;
	size_t ulLen;
	CHAR* pszProvider;
	SECURITY_STATUS lRet = NCryptEnumStorageProviders(&dwCount, &pProviderList, 0);
	if (lRet != ERROR_SUCCESS)
	{
		THROW_JS_ERROR(env, "Error enumerating CNG providers", "cngEnumerateProviders", HH_ENUM_PROV_ERROR, lRet);
		return;
	}
	while (bOK && i < dwCount)
	{
		ulLen = wcstombs(NULL, pProviderList[i].pszName, 0);
		pszProvider = (CHAR*) LocalAlloc(LMEM_ZEROINIT, ulLen + 1);
		if ((bOK = pszProvider ? true : false))
		{
			wcstombs(pszProvider, pProviderList[i].pszName, ulLen + 1);
			out.push_back(pszProvider);
			LocalFree(pszProvider);
		}
		i++;
	}
	NCryptFreeBuffer(pProviderList);
	if (!bOK) THROW_JS_ERROR(env, "Out of memory", "cngEnumerateProviders", HH_OUT_OF_MEM_ERROR);
}

Napi::Value capiGenerateKeyPair(const Napi::Env env, const std::string provider, const DWORD dwType, const DWORD ulKeyLen, KeyHandler& handler, int* hHandle)
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
	
	std::string container(szContainer);
	*hHandle = handler.AddKey(hKey, container, dwType, provider);
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded);

	LocalFree(pbEncoded);
	LocalFree(pInfo);
	CryptReleaseContext(hProv, 0);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
}

Napi::Value cngGenerateKeyPair(const Napi::Env env, const std::wstring& provider, const DWORD ulKeyLen, KeyHandler& handler, int* hHandle)
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
		(stat = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE*) &dwExport, sizeof(DWORD), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (BYTE*) &dwKeyUsage, sizeof(DWORD), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (BYTE*) &ulKeyLen, sizeof(DWORD), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptSetProperty(hKey, NCRYPT_UI_POLICY_PROPERTY, (BYTE*) &pPolicy, sizeof(NCRYPT_UI_POLICY), NCRYPT_PERSIST_FLAG)) != ERROR_SUCCESS ||
		(stat = NCryptFinalizeKey(hKey, NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG)) != ERROR_SUCCESS
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

	std::wstring temp(szName);
	std::string keyName(temp.cbegin(), temp.cend());
	std::string provName(provider.cbegin(), provider.cend());
	*hHandle = handler.AddKey(hKey, keyName, 0, provName);
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pbEncoded, cbEncoded);
	LocalFree(pbEncoded);
	LocalFree(pInfo);
	NCryptFreeObject(hProv);
	return Napi::TypedArrayOf<uint8_t>::New(env, cbEncoded, buffer, 0, napi_uint8_array);
}


// * * * * * * * * * * * * * * *
// Key/Certificates wrapper
// * * * * * * * * * * * * * * *
KeyWrap::KeyWrap(const ULONG_PTR hKey, const std::string& container, const DWORD dwType, const std::string& provider)
{
	this->isKey = true;
	this->hKey = hKey;
	this->keyName.assign(container);
	this->dwType = dwType;
	this->provider.assign(provider);
}
KeyWrap::KeyWrap(const std::string& subject, const std::string& issuer, const std::string& serial)
{
	this->isKey = false;
	this->hKey = NULL;
	this->subject.assign(subject);
	this->issuer.assign(issuer);
	this->serial.assign(serial);
}
KeyWrap::KeyWrap(const char* subject, const char* issuer, const char* serial)
{
	this->isKey = false;
	this->hKey = NULL;
	this->subject.assign(subject);
	this->issuer.assign(issuer);
	this->serial.assign(serial);
}
KeyWrap::~KeyWrap()
{
	if(this->isKey && this->hKey)
	{
		if (this->dwType != 0) CryptDestroyKey(this->hKey);
		else NCryptFreeObject(this->hKey);
	}
}
KeyHandler::KeyHandler()
{
	this->__handlers = 0;
}
KeyHandler::~KeyHandler()
{
	for (std::map<int, KeyWrap*>::iterator it = this->__keys.begin(); it != this->__keys.end(); ++it) delete it->second;
}
int KeyHandler::AddKey(const ULONG_PTR hKey, const std::string& keyName, const DWORD dwType, const std::string& provider)
{
	KeyWrap* key = new KeyWrap(hKey, keyName, dwType, provider);
	int hHandle = ++this->__handlers;
	this->__keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
int KeyHandler::AddKey(const std::string& subject, const std::string& issuer, const std::string& serial)
{
	KeyWrap* key = new KeyWrap(subject, issuer, serial);
	int hHandle = ++this->__handlers;
	this->__keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
int KeyHandler::AddKey(const char* subject, const char* issuer, const char* serial)
{
	KeyWrap* key = new KeyWrap(subject, issuer, serial);
	int hHandle = ++this->__handlers;
	this->__keys.insert(std::pair<int, KeyWrap*>(hHandle, key));
	return hHandle;
}
void KeyHandler::ReleaseKey(const int hHandle)
{
	std::map<int, KeyWrap*>::iterator it = this->__keys.find(hHandle);
	if (it != this->__keys.end())
	{
		delete it->second;
		this->__keys.erase(hHandle);
	}
}
void KeyHandler::DeleteKey(const int hHandle)
{
	std::map<int, KeyWrap*>::iterator it = this->__keys.find(hHandle);
	if (it != this->__keys.end())
	{
		if (it->second->isKey)
		{
			if (it->second->dwType != 0)
			{
				HCRYPTPROV hProv;
				CryptAcquireContextA(&hProv, it->second->keyName.c_str(), it->second->provider.c_str(), it->second->dwType, CRYPT_DELETEKEYSET);
			}
			else NCryptDeleteKey(it->second->hKey, 0);
			it->second->hKey = NULL;
		}
		delete it->second;
		this->__keys.erase(hHandle);
	}
}
KeyWrap* KeyHandler::GetKey(const int hHandle)
{
	KeyWrap* ret = NULL;
	std::map<int, KeyWrap*>::iterator it = this->__keys.find(hHandle);
	if (it != this->__keys.end()) ret = it->second;
	return ret;
}
std::map<int, KeyWrap*>& KeyHandler::GetHandlers()
{
	return this->__keys;
}


// * * * * * * * * * * * * * * *
// The API itself
// * * * * * * * * * * * * * * *
Hamahiri::Hamahiri(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
	Napi::Env env = info.Env();
	// TODO: What else?
}
Napi::Value Hamahiri::EnumerateDevices(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	this->__rsaProviders.clear();
	this->__aesProviders.clear();
	this->__CNGProviders.clear();
	capiEnumerateProviders(env, PROV_RSA_FULL, this->__rsaProviders);
	if (env.IsExceptionPending()) return env.Null();
	capiEnumerateProviders(env, PROV_RSA_AES, this->__aesProviders);
	if (env.IsExceptionPending()) return env.Null();
	cngEnumerateProviders(env, this->__CNGProviders);
	if (env.IsExceptionPending()) return env.Null();
	Napi::Array ret = Napi::Array::New(env, this->__rsaProviders.size() + this->__aesProviders.size() + this->__CNGProviders.size());
	size_t i = 0, j = 0;
	while (i < this->__rsaProviders.size()) ret[j++] = Napi::String::New(env, this->__rsaProviders.at(i++).c_str());
	i = 0;
	while (i < this->__aesProviders.size()) ret[j++] = Napi::String::New(env, this->__aesProviders.at(i++).c_str());
	i = 0;
	while (i < this->__CNGProviders.size()) ret[j++] = Napi::String::New(env, this->__CNGProviders.at(i++).c_str());
	return ret;
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

	if (this->__rsaProviders.size() == 0 && this->__aesProviders.size() == 0 && this->__CNGProviders.size() == 0)
	{
		capiEnumerateProviders(env, PROV_RSA_FULL, this->__rsaProviders);
		if (env.IsExceptionPending()) return env.Null();
		capiEnumerateProviders(env, PROV_RSA_AES, this->__aesProviders);
		if (env.IsExceptionPending()) return env.Null();
		cngEnumerateProviders(env, this->__CNGProviders);
		if (env.IsExceptionPending()) return env.Null();
	}
	std::string provider = info[0].As<Napi::String>().Utf8Value();
	bool bLegacy = true, bFound = false;
	DWORD dwType = PROV_RSA_FULL;
	size_t i = 0;
	while (!bFound && i < this->__rsaProviders.size()) bFound = this->__rsaProviders.at(i++).compare(provider) == 0;
	if (!bFound)
	{
		i = 0;
		dwType = PROV_RSA_AES;
		while (!bFound && i < this->__aesProviders.size()) bFound = this->__aesProviders.at(i++).compare(provider) == 0;
		if (!bFound)
		{
			bLegacy = false;
			dwType = 0;
			i = 0;
			while (!bFound && i < this->__CNGProviders.size()) bFound = this->__CNGProviders.at(i++).compare(provider) == 0;
		}
	}
	if (!bFound)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "The device argument does not correspond to an installed cryptographic device"), "generateKeyPair", HH_ARGUMENT_ERROR);
		return env.Null();
	}

	int hHandle = 0;
	Napi::Value pubKey;
	if (bLegacy) pubKey = capiGenerateKeyPair(env, provider, dwType, info[1].As<Napi::Number>().Int32Value(), this->__handler, &hHandle);
	else
	{
		std::wstring cngProv(provider.cbegin(), provider.cend());
		pubKey = cngGenerateKeyPair(env, cngProv, info[1].As<Napi::Number>().Int32Value(), this->__handler, &hHandle);
	}
	if (env.IsExceptionPending()) return env.Null();

	Napi::Object ret = Napi::Object::New(env);
	ret.Set("privKey", hHandle);
	ret.Set("pubKey", pubKey.As<Napi::TypedArrayOf<uint8_t>>());
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
	this->__handler.ReleaseKey(info[0].As<Napi::Number>().Int32Value());
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
	this->__handler.DeleteKey(info[0].As<Napi::Number>().Int32Value());
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
	switch (info[1].As<Napi::Number>().Uint32Value())
	{
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		break;
	default:
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Unsupported signing algorithm"), "sign", HH_UNSUPPORTED_MECHANISM_ERROR);
		return env.Null();
	}
	KeyWrap* wrapper = this->__handler.GetKey(info[2].As<Napi::Number>().Int32Value());
	if (!wrapper)
	{
		THROW_JS_ERROR(env, Napi::TypeError::New(env, "Invaid signing key handle"), "sign", HH_INVALID_KEY_HANDLE);
		return env.Null();
	}
	ULONG_PTR hKey;
	if (wrapper->isKey) hKey = wrapper->hKey;
	else
	{
		// TODO: Get private key using the signer certificate
		hKey = NULL;
	}

	// TODO: Sign hash with CryptoAPI
	uint8_t signature[] = {
		(uint8_t) 0x73, (uint8_t) 0x69, (uint8_t) 0x6d, (uint8_t) 0x75, (uint8_t) 0x6c, (uint8_t) 0x61, (uint8_t) 0xc3, (uint8_t) 0xa7,
		(uint8_t) 0xc3, (uint8_t) 0xa3, (uint8_t) 0x6f, (uint8_t) 0x20, (uint8_t) 0x64, (uint8_t) 0x65, (uint8_t) 0x20, (uint8_t) 0x61,
		(uint8_t) 0x73, (uint8_t) 0x73, (uint8_t) 0x69, (uint8_t) 0x6e, (uint8_t) 0x61, (uint8_t) 0x74, (uint8_t) 0x75, (uint8_t) 0x72,
		(uint8_t) 0x61, (uint8_t) 0x20, (uint8_t) 0x64, (uint8_t) 0x69, (uint8_t) 0x67, (uint8_t) 0x69, (uint8_t) 0x74, (uint8_t) 0x61
	};
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, signature, 32);
	return Napi::TypedArrayOf<uint8_t>::New(env, 32, buffer, 0, napi_uint8_array);
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
	this->__handler.AddKey("CN = Francisvaldo Genevaldo das Torres 1601581365803", "CN = Common Name for All Cats End User CA, OU = PKI Ruler for All Cats, O = PKI Brazil, C = BR", "1A");

	std::map<int, KeyWrap*> keys = this->__handler.GetHandlers();
	std::vector<Napi::Object> certs;
	for (std::map<int, KeyWrap*>::iterator it = keys.begin(); it != keys.end(); ++it)
	{
		if (!it->second->isKey)
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
