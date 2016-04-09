#include <math.h>
#include <string.h>

#include <node.h>
#include <node_buffer.h>
#include <nan.h>

#include "fastpbkdf2.h"

namespace {

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Value;
using v8::Handle;
using v8::Uint8Array;
using v8::ArrayBuffer;

#define CHECK_INFO\
	Nan::HandleScope scope;\
\
	ssize_t passlen = 0;\
	ssize_t saltlen = 0;\
	ssize_t keylen = 0;\
	ssize_t iter = 0;\
	String::Utf8Value passObj(info[0]->ToObject());\
	const char* pass = *passObj;\
	const char* type_error = nullptr;\
\
	if (info.Length() != 4) {\
		type_error = "Wrong number of arguments: Expected 4 (password, salt, iterations, keylen)";\
		goto err;\
	}\
	if (!info[0]->IsString() && !node::Buffer::HasInstance(info[0])) {\
		type_error = "Password must be String or Buffer type";\
		goto err;\
	}\
	passlen = passObj.length();\
	if (passlen < 0 || passlen > 1024) {\
		type_error = "Bad password length: must be 0 <= len <= 1024";\
		goto err;\
	}\
	if (!node::Buffer::HasInstance(info[1])) {\
		type_error = "Salt must be Buffer type";\
		goto err;\
	}\
	saltlen = node::Buffer::Length(info[1]);\
	if (saltlen < 0 || saltlen > 1024) {\
		type_error = "Bad salt length: must be 0 <= len <= 1024";\
		goto err;\
	}\
	memcpy(salt, node::Buffer::Data(info[1]), saltlen);\
\
	if (!info[2]->IsNumber()) {\
		type_error = "Iterations must be Number type";\
		goto err;\
	}\
	iter = info[2]->Int32Value();\
	if (iter <= 0) {\
		type_error = "Iterations must be greater than 0";\
		goto err;\
	}\
	if (!info[3]->IsNumber()) {\
		type_error = "Key length must be a Number type";\
		goto err;\
	}\
	keylen = info[3]->Int32Value();\
	if (keylen <= 0) {\
		type_error = "Key length must be greater than 0";\
		goto err;\
	}

// printf("pass: %s, passlen: %d, salt: %s, saltlen: %d\n", pass, passlen, salt, saltlen);

void sha1(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	char salt[1024] = {};
	char digest[1024] = {};

	CHECK_INFO

	fastpbkdf2_hmac_sha1(
		(uint8_t*) pass, passlen,
		(uint8_t*) salt, saltlen,
		iter,
		(uint8_t*) digest, keylen);

	return info.GetReturnValue().Set(Nan::CopyBuffer(digest, keylen).ToLocalChecked());

err:
	Nan::ThrowError( Nan::New<String>(type_error).ToLocalChecked());
}

void sha256(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	char salt[1024] = {};
	char digest[1024] = {};

	CHECK_INFO

	fastpbkdf2_hmac_sha256(
		(uint8_t*) pass, passlen,
		(uint8_t*) salt, saltlen,
		iter,
		(uint8_t*) digest, keylen);

	return info.GetReturnValue().Set(Nan::CopyBuffer(digest, keylen).ToLocalChecked());

err:
	Nan::ThrowError( Nan::New<String>(type_error).ToLocalChecked());
}

void sha512(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	char salt[1024] = {};
	char digest[1024] = {};

	CHECK_INFO

	fastpbkdf2_hmac_sha512(
		(uint8_t*) pass, passlen,
		(uint8_t*) salt, saltlen,
		iter,
		(uint8_t*) digest, keylen);

	return info.GetReturnValue().Set(Nan::CopyBuffer(digest, keylen).ToLocalChecked());

err:
	Nan::ThrowError( Nan::New<String>(type_error).ToLocalChecked());
}

NAN_MODULE_INIT(Init) {
	v8::Local<v8::Function> sha1Fn = Nan::GetFunction(
		Nan::New<v8::FunctionTemplate>(sha1)).ToLocalChecked();
	Nan::Set(target, Nan::New("sha1").ToLocalChecked(), sha1Fn);

	v8::Local<v8::Function> sha256Fn = Nan::GetFunction(
		Nan::New<v8::FunctionTemplate>(sha256)).ToLocalChecked();
	Nan::Set(target, Nan::New("sha256").ToLocalChecked(), sha256Fn);

	v8::Local<v8::Function> sha512Fn = Nan::GetFunction(
		Nan::New<v8::FunctionTemplate>(sha512)).ToLocalChecked();
	Nan::Set(target, Nan::New("sha512").ToLocalChecked(), sha512Fn);
}

NODE_MODULE(addon, Init)

}
