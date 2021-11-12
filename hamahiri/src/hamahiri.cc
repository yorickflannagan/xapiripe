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
				THROW_JS_ERROR(env, "Out of memory", "capiEnumerateProviders", HH_OUT_OF_MEM_ERROR);
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


// * * * * * * * * * * * * * * *
// Key/Certificates wrapper
// * * * * * * * * * * * * * * *
KeyWrap::KeyWrap(const ULONG_PTR hKey)
{
	this->isKey = true;
	this->hKey = hKey;
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
		// TODO: Release hKey with CryptoAPI
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
int KeyHandler::AddKey(const ULONG_PTR hKey)
{
	KeyWrap* key = new KeyWrap(hKey);
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
	std::vector<std::string> providers;
	capiEnumerateProviders(env, PROV_RSA_FULL, providers);
	if (env.IsExceptionPending()) return env.Null();
	capiEnumerateProviders(env, PROV_RSA_AES, providers);
	if (env.IsExceptionPending()) return env.Null();
	cngEnumerateProviders(env, providers);
	if (env.IsExceptionPending()) return env.Null();
	Napi::Array ret = Napi::Array::New(env, providers.size());
	for (unsigned int i = 0; i < providers.size(); i++) ret[i] = Napi::String::New(env, providers.at(i).c_str());
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

	// TODO: Generate RSA key pair using CryptoAPI
	ULONG_PTR hKey = NULL;
	uint8_t pubKey[] = {
		(uint8_t) 0x74, (uint8_t) 0x72, (uint8_t) 0x61, (uint8_t) 0x74, (uint8_t) 0x61, (uint8_t) 0x2d, (uint8_t) 0x73, (uint8_t) 0x65,
		(uint8_t) 0x20, (uint8_t) 0x64, (uint8_t) 0x61, (uint8_t) 0x20, (uint8_t) 0x73, (uint8_t) 0x69, (uint8_t) 0x6d, (uint8_t) 0x75,
		(uint8_t) 0x6c, (uint8_t) 0x61, (uint8_t) 0xc3, (uint8_t) 0xa7, (uint8_t) 0xc3, (uint8_t) 0xa3, (uint8_t) 0x6f, (uint8_t) 0x20,
		(uint8_t) 0x64, (uint8_t) 0x65, (uint8_t) 0x20, (uint8_t) 0x75, (uint8_t) 0x6d, (uint8_t) 0x61, (uint8_t) 0x20, (uint8_t) 0x63,
		(uint8_t) 0x68, (uint8_t) 0x61, (uint8_t) 0x76, (uint8_t) 0x65, (uint8_t) 0x20, (uint8_t) 0x70, (uint8_t) 0xc3, (uint8_t) 0xba,
		(uint8_t) 0x62, (uint8_t) 0x6c, (uint8_t) 0x69, (uint8_t) 0x63, (uint8_t) 0x61, (uint8_t) 0x20, (uint8_t) 0x65, (uint8_t) 0x6e,
		(uint8_t) 0x63, (uint8_t) 0x6f, (uint8_t) 0x64, (uint8_t) 0x61, (uint8_t) 0x64, (uint8_t) 0x61, (uint8_t) 0x20, (uint8_t) 0x65,
		(uint8_t) 0x6d, (uint8_t) 0x20, (uint8_t) 0x44, (uint8_t) 0x45, (uint8_t) 0x52		
	};
	Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, pubKey, 61);

	int hHandle = this->__handler.AddKey(hKey);
	Napi::Object ret = Napi::Object::New(env);
	ret.Set("privKey", hHandle);
	ret.Set("pubKey", Napi::TypedArrayOf<uint8_t>::New(env, 61, buffer, 0, napi_uint8_array));
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
