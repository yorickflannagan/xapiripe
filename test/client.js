'use strict';

function doFetch(url, init) {
	let output = document.getElementById('output');
	if (!output) throw 'Output textarea not found. Cannot show test results';
	output.value = 'Status code: ';
	window.fetch(url, init)
	.then((response) => {
		output.value += response.status;
		if (response.ok) {
			output.value += '\nResponse body:\n';
			response.text().then((value) => { output.value += value; });
		}
		else {
			output.value += '\nHTTP status text: ';
			output.value += response.statusText;
		}
	}).catch((reason) => {
		output.value = 'Connection failed due to following error: ';
		output.value += reason.toString();
	});
}

function enumerateDevices() {
	doFetch('http://127.0.0.1:9171/enroll', {
		method: 'GET',
		mode: 'cors',
		cache: 'no-store'
	});
}
function generateCSR() {
	let device = document.getElementById('device');
	let cn = document.getElementById('cn');
	let keysize = document.getElementById('keysize');
	let algorithm = document.getElementById('algorithm');
	let additional = document.getElementById('additional');
	if (!(device && cn && keysize && algorithm && additional)) throw 'Not all input fields were found. Cannot test service';
	let rdn;
	if (cn.value) rdn = { cn: cn.value };
	let param = new Object();
	if (device.value) param = Object.defineProperty(param, 'device',  { value: device.value });
	if (keysize.value) param = Object.defineProperty(param, 'keySize', { value: Number.parseInt(keysize.value) });
	if (algorithm.value) param = Object.defineProperty(param, 'signAlg', { value: Number.parseInt(algorithm.value) });
	if (rdn) param = Object.defineProperty(param, 'rdn', { value: rdn });
	if (additional.value) param = Object.defineProperty(param, additional.value, { value: 'Any value' });
	let body = JSON.stringify(param, [ 'device', 'keySize', 'signAlg', 'rdn', 'cn', additional.value ]);
	doFetch('http://127.0.0.1:9171/enroll', {
		method: 'POST',
		mode: 'cors',
		cache: 'no-store',
		headers: { 'Content-Type': 'application/json' },
		body: new TextEncoder().encode(body)
	});
}
function installCertificates() {
	let pkcs7 = document.getElementById('pkcs7');
	if (!pkcs7) throw 'Input text area not found. Cannot test service';
	let body = JSON.stringify({ pkcs7: pkcs7.value });
	doFetch('http://127.0.0.1:9171/enroll', {
		method: 'PUT',
		mode: 'cors',
		cache: 'no-store',
		headers: { 'Content-Type': 'application/json' },
		body: new TextEncoder().encode(body)
	});
}

function enumerateCertificates() {
	doFetch('http://127.0.0.1:9171/sign', {
		method: 'GET',
		mode: 'cors',
		cache: 'no-store'
	});
}
function sign() {
	let handle = document.getElementById('handle');
	let attach = document.getElementById('attach');
	let signAlg = document.getElementById('signAlg');
	let addSigningTime = document.getElementById('addSigningTime');
	let policy = document.getElementById('policy');
	let commitmentType = document.getElementById('commitmentType');
	let addSign = document.getElementById('addSign');
	let toBeSigned = document.getElementById('toBeSigned');
	if (!(handle && attach && signAlg && addSigningTime && policy && commitmentType && addSign && toBeSigned)) throw 'Not all input fields were found. Cannot test service';

	let param = new Object();
	if (handle.value) param = Object.defineProperty(param, 'handle', { value: Number.parseInt(handle.value) });
	if (toBeSigned.value) param = Object.defineProperty(param, 'toBeSigned', { value: { data: toBeSigned.value }});
	if (attach.value) param = Object.defineProperty(param, 'attach', { value: attach.value === 'true' ? true : false });
	if (signAlg.value) param = Object.defineProperty(param, 'algorithm', { value: Number.parseInt(signAlg.value) });
	let cades;
	if (policy.value|| addSigningTime.value || commitmentType.value ) cades = new Object();
	if (policy.value) cades = Object.defineProperty(cades, 'policy', { value: policy.value });
	if (addSigningTime) cades = Object.defineProperty(cades, 'addSigningTime', { value: addSigningTime.value === 'true' ? true : false });
	if (commitmentType.value) cades = Object.defineProperty(cades, 'commitmentType', { value: commitmentType.value });
	if (cades) param = Object.defineProperty(param, 'cades', { value: cades });
	if (addSign.value) param = Object.defineProperty(param, addSign.value, { value: 'Any value' });
	let body = JSON.stringify(param, [ 'handle', 'toBeSigned', 'data', 'binary', 'attach' , 'algorithm', 'cades', 'policy', 'addSigningTime', 'commitmentType', addSign.value ]);

	doFetch('http://127.0.0.1:9171/sign', {
		method: 'POST',
		mode: 'cors',
		cache: 'no-store',
		headers: { 'Content-Type': 'application/json' },
		body: new TextEncoder().encode(body)
	});
}
function verify() {
	let verifyTrustworthy = document.getElementById('verifyTrustworthy');
	let getSignerIdentifier = document.getElementById('getSignerIdentifier');
	let getSignedContent = document.getElementById('getSignedContent');
	let getSigningTime = document.getElementById('getSigningTime');
	let addVerify = document.getElementById('addVerify');
	let cms = document.getElementById('cms');
	if (!(verifyTrustworthy && getSignerIdentifier && getSignedContent && getSigningTime && addVerify && cms)) throw 'Not all input fields were found. Cannot test service';

	let param = new Object();
	if (verifyTrustworthy.value) param = Object.defineProperty(param, 'verifyTrustworthy', { value: verifyTrustworthy.value === 'true' ? true : false });
	if (getSignerIdentifier.value) param = Object.defineProperty(param, 'getSignerIdentifier', { value: getSignerIdentifier.value === 'true' ? true : false });
	if (getSignedContent.value) param = Object.defineProperty(param, 'getSignedContent', { value: getSignedContent.value === 'true' ? true : false });
	if (getSigningTime.value) param = Object.defineProperty(param, 'getSigningTime', { value: getSigningTime.value === 'true' ? true : false });
	if (addVerify.value) param = Object.defineProperty(param, addVerify.value, { value: 'Any value' });
	if (cms.value) param = Object.defineProperty(param, 'pkcs7', { value: { data: cms.value }});
	let body = JSON.stringify(param, [ 'verifyTrustworthy', 'getSignerIdentifier', 'getSignedContent', 'getSigningTime', 'pkcs7', 'data', addVerify.value ]);

	doFetch('http://127.0.0.1:9171/verify', {
		method: 'POST',
		mode: 'cors',
		cache: 'no-store',
		headers: { 'Content-Type': 'application/json' },
		body: new TextEncoder().encode(body)
	});
}