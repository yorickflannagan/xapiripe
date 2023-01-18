#include "lock.h"
#include <uv.h>
#include <windows.h>

using namespace Napi;

#define LOCK_REGION		0xFFFF0000

Lock::Lock(const Napi::CallbackInfo& info) : ObjectWrap(info) {}

Napi::Value Lock::Flock(const Napi::CallbackInfo& info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		Napi::TypeError::New(env, "Argument must be a file handle").ThrowAsJavaScriptException();
		return env.Null();
	}
	int fd = info[0].As<Napi::Number>().Int32Value();
	HANDLE hFile = (HANDLE) uv_get_osfhandle(fd);

	BOOL rv = LockFile(hFile, 0, 0, LOCK_REGION, 0);
	return Napi::Boolean::New(env, rv == 0 ? false : true);
}

Napi::Value Lock::Funlock(const Napi::CallbackInfo & info)
{
	Napi::Env env = info.Env();
	if (info.Length() < 1)
	{
		Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
		return env.Null();
	}
	if (!info[0].IsNumber())
	{
		Napi::TypeError::New(env, "Argument must be a file handle").ThrowAsJavaScriptException();
		return env.Null();
	}
	int fd = info[0].As<Napi::Number>().Int32Value();
	HANDLE hFile = (HANDLE) uv_get_osfhandle(fd);

	BOOL rv = UnlockFile(hFile, 0, 0, LOCK_REGION, 0);
	return Napi::Boolean::New(env, rv == 0 ? false : true);
}


Napi::Function Lock::GetClass(Napi::Env env)
{
    return DefineClass(env, "Lock",
	{
        Lock::InstanceMethod("flock",   &Lock::Flock),
		Lock::InstanceMethod("funlock", &Lock::Funlock)
    });
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    Napi::String name = Napi::String::New(env, "Lock");
    exports.Set(name, Lock::GetClass(env));
    return exports;
}

NODE_API_MODULE(addon, Init)
