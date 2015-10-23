{
	"targets": [{
		"target_name": "fastpbkdf2",
		"sources": [
			"binding.cc",
			"fastpbkdf2.h",
			"fastpbkdf2.c"
		],
		"include_dirs": [
			"<!(node -e \"require('nan')\")"
		],
		"cflags" : [ "-std=c99", "-O3", "-fPIC"],
		"cflags_cc": [ "-std=c99", "-O3", "-fPIC" ],
		"conditions": [
		]
	}]
}
