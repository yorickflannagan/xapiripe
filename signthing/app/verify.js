/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 * 		diego.sohsten@gmail.com
 *
 * Signithing - desktop application UI
 * See https://bitbucket.org/yorick-flannagan/signithing/src/master/
 * verify.js - verify.html behaviour
 * 
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3.0 of
 * the License, or (at your option) any later version.
 *
 * This application is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See https://opensource.org/licenses/LGPL-3.0
 *
 */
'use strict';

function vrfyToggle(elem) { elem.value = elem.value == '+' ? '-' : '+'; }
function vrfyReset(btn, div)
{
	btn.value = '+';
	if (div.classList.contains('show')) div.classList.remove('show');
}
function vrfyValidateInput(elem)
{
	let isValid = elem.value;
	if (!isValid) window.showMessage({
		message: 'You must select a CMS signed file',
		type: 'error',
		title: 'Insufficient data input'
	});
	return isValid;
}

let vrfyLoaded = false;		// verify-loaded event control
let vrfyHandle = 0;			// parsed CMS Signed Data handle
let vrfyFD = 0;				// CMS encapsulated content info handle
document.addEventListener('verify-loaded', () => {
	try
	{
		// UI elements
		const iframe = document.getElementById('verify-div');
		const txtEnvelope = iframe.contentWindow.document.getElementById('txt-envelope');
		const btnEnvelope = iframe.contentWindow.document.getElementById('btn-envelope');
		const txtContents = iframe.contentWindow.document.getElementById('txt-contents');
		const btnContents = iframe.contentWindow.document.getElementById('btn-contents');
		const btnSignature = iframe.contentWindow.document.getElementById('btn-signature');
		const divSignature = iframe.contentWindow.document.getElementById('div-sig');
		const txtSignature = iframe.contentWindow.document.getElementById('txt-signature');
		const btnCertificate = iframe.contentWindow.document.getElementById('btn-certificate');
		const txtCertificate = iframe.contentWindow.document.getElementById('txt-certificate');
		const divCertificate = iframe.contentWindow.document.getElementById('div-cert');
		const btnSid = iframe.contentWindow.document.getElementById('btn-sid');
		const divSid = iframe.contentWindow.document.getElementById('div-sid');
		const txtSid = iframe.contentWindow.document.getElementById('txt-sid');
		const btnShowEncap = iframe.contentWindow.document.getElementById('btn-showEncap');
		const divEncap = iframe.contentWindow.document.getElementById('div-encap');
		const docNotLoaded = iframe.contentWindow.document.getElementById('doc-not-loaded');
		const docLoaded = iframe.contentWindow.document.getElementById('doc-loaded');
		const btnClose = iframe.contentWindow.document.getElementById('close');

		// Recall configuration
		const cfg = window.getConfig();

		// Select CMS envelope button
		if (!vrfyLoaded)
		btnEnvelope.addEventListener('click', () => {
			let choice = window.openFile({
				title: 'Select a CMS signed-data enveloped file',
				defaultPath: cfg.appOptions.lastFolder,
				filters: [
					{ name: 'PKCS #7 files', extensions: ['p7b', 'pem']},
					{ name: 'All files',     extensions: ['*']}
				],
				properties: [ 'openFile' ] 
			});
			if (choice !== undefined)
			{
				txtEnvelope.value = choice[0];
				cfg.appOptions.lastFolder = window.parentFolder(choice[0]);
			}
		});

		// Select signed contents button
		if (!vrfyLoaded)
		btnContents.addEventListener('click', () => {
			let choice = window.openFile({
				title: 'Select the signed file (if it is not attached to the envelope)',
				defaultPath: cfg.appOptions.lastFolder,
				filters: [ { name: 'All files', extensions: ['*']}],
				properties: [ 'openFile' ] 
			});
			if (choice !== undefined)
			{
				txtContents.value = choice[0];
				cfg.appOptions.lastFolder = window.parentFolder(choice[0]);
			}
		});

		// Verify signature button
		if (!vrfyLoaded)
		btnSignature.addEventListener('click', () => {
			if (!vrfyValidateInput(txtEnvelope)) return;
			if (vrfyHandle == 0) vrfyHandle = window.parseCMSSignedData({
				pkcs7: txtEnvelope.value,
				contents: txtContents.value
			});
			let success = window.verifySignature(vrfyHandle);
			let time = success ? window.getSigningTime(vrfyHandle) : '';
			txtSignature.innerHTML = 'Signature cryptographic validation:'
			if (success) txtSignature.innerHTML += ' success! Document signed at ' + time
			else  txtSignature.innerHTML += ' failure"!';
			divSignature.classList.toggle('show');
			vrfyToggle(btnSignature);
		});

		// Verify Certificate trustworthy button
		if (!vrfyLoaded)
		btnCertificate.addEventListener('click', () => {
			if (!vrfyValidateInput(txtEnvelope)) return;
			if (vrfyHandle == 0) vrfyHandle = window.parseCMSSignedData({
				pkcs7: txtEnvelope.value,
				contents: txtContents.value
			});
			txtCertificate.innerHTML = 'Signing certificate trustworthy validation:';
			txtCertificate.innerHTML += window.verifySigningCertificate(vrfyHandle) ? ' successful!' : ' failure...';
			divCertificate.classList.toggle('show');
			vrfyToggle(btnCertificate);
		});

		// Show signer identifier button
		if (!vrfyLoaded)
		btnSid.addEventListener('click', () => {
			if (!vrfyValidateInput(txtEnvelope)) return;
			if (vrfyHandle == 0) vrfyHandle = window.parseCMSSignedData({
				pkcs7: txtEnvelope.value,
				contents: txtContents.value
			});
			let sid = window.getSignerIdentifier(vrfyHandle);
			if (sid.keyIdentifier) txtSid.innerHTML = 'Subject key identifier: ' + sid.keyIdentifier;
			else
			{
				txtSid.innerHTML = 'Signer common name: ';
				txtSid.innerHTML += sid.commonName;
				txtSid.innerHTML += '. Certificate serial number: ';
				txtSid.innerHTML += sid.serialNumber;
			}
			divSid.classList.toggle('show');
			vrfyToggle(btnSid);
		});

		// Show signed contents button
		if (!vrfyLoaded)
		btnShowEncap.addEventListener('click', () => {
			if (!vrfyValidateInput(txtEnvelope)) return;
			if (vrfyHandle == 0) vrfyHandle = window.parseCMSSignedData({
				pkcs7: txtEnvelope.value,
				contents: txtContents.value
			});
			if (vrfyFD == 0)
			{
				let encap = window.getContentInfo(vrfyHandle);
				if (encap)
				{
					vrfyFD = window.createTempFile();
					window.writeFile({ handle: vrfyFD, contents: encap });
					docLoaded.style = 'display:block';
					window.openURI(vrfyFD);
				}
				else docNotLoaded.style = 'display: block';
			}
			divEncap.classList.toggle('show');
			vrfyToggle(btnShowEncap);
		});

		// Close button
		if (!vrfyLoaded)
		btnClose.addEventListener('click', () => {
			if (vrfyHandle != 0) window.releaseCMSHandle(vrfyHandle);
			window.updateConfig(cfg);
			vrfyHandle = 0;
			txtEnvelope.value = '';
			txtContents.value = '';
			txtSignature.innerHTML = '';
			txtCertificate.innerHTML = '';
			txtSid.innerHTML = '';
			docNotLoaded.style = 'display: none';
			docLoaded.style = 'display: none';
			vrfyReset(btnSignature, divSignature);
			vrfyReset(btnCertificate, divCertificate);
			vrfyReset(btnSid, divSid);
			vrfyReset(btnShowEncap, divEncap);
			iframe.style = 'display: none';
			if (vrfyFD != 0) window.releaseTempFile(vrfyFD);
			vrfyFD = 0;
			window.retreatCall();
		});
	}
	catch (err)
	{
		window.showMessage({
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Error on loading page',
			detail: 'The application is not functioning properly'
		});
	}
	vrfyLoaded = true;
});