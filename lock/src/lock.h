#pragma once

#include <napi.h>

class Lock : public Napi::ObjectWrap<Lock>
{
public:
	Lock(const Napi::CallbackInfo&);
	Napi::Value Flock(const Napi::CallbackInfo&);
	Napi::Value Funlock(const Napi::CallbackInfo&);

	static Napi::Function GetClass(Napi::Env);
};
