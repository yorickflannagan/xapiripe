/**
 * Node.js native addon mock
 */
const { SignerIdentifier } = require('./module');

module.exports.XPEBasicSign = () => {
	return	'-----BEGIN PKCS7-----\n' +
			'Fake PKCS #7s\n' +
			'-----END PKCS7-----';
}
module.exports.XPEListCertificates = () => {
	return ['John Doe Signining Certificate', 'John Doe SSL certificate'];
}
module.exports.XPEParseCMSSignedData = () => {
	return 128;
}
module.exports.XPEVerifySignature = () => {
	return true;
}
module.exports.XPEGetSigningTime = () => {
	return '2021-08-12T20:17:46.384Z';
}
module.exports.XPEVerifyCertificate = () => {
	return true;
}
module.exports.XPEGetSignerIdentifier = () => {
	return new SignerIdentifier('John Doe Signining Certificate', '245eee1daa3842b1babe09f9c349d2b1');;
}
module.exports.XPEGetEncapContent = () => {
	let encoded = new TextEncoder();
	return encoded.encode('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec eu viverra ante. Suspendisse at scelerisque arcu. Phasellus fermentum bibendum odio a dignissim. Ut vel bibendum lacus, vel faucibus ante. Ut sit amet tincidunt nisi. In rutrum mattis nisl eget rutrum. In sed ipsum eu mi rhoncus fermentum. Donec lobortis facilisis eros, at iaculis risus pellentesque in. Etiam blandit imperdiet odio in placerat. Quisque enim odio, egestas ut pharetra non, hendrerit sit amet odio.');
}
module.exports.XPEReleaseCMSSignedData = () => {
	return 0;
}