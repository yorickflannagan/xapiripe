/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020-2022 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 *
 * Signithing - desktop application UI
 * See https://bitbucket.org/yorick-flannagan/signithing/src/master/
 * preload.js - Electron renderer process
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

const { contextBridge, ipcRenderer } = require('electron');
const path = require('path');
const fs = require('fs');


/** * * * * * * * * * * * * * * *
 * UI exposed window functions
 */

/**
 * - askDialog
 * Exibe diálogo para tomada de decisão
 * - options: see https://www.electronjs.org/docs/api/dialog#dialogshowmessageboxbrowserwindow-options
 * Return
 * - Object:
 * 		response: índice do botão selecionado (0 = Cancelar, 1 - OK)
 * 		checkboxChecked: true se a escolha deve ser lembrada
 */
contextBridge.exposeInMainWorld('askDialog', (options) => {
	return ipcRenderer.sendSync('ask-dialog', options);
});

/**
 * - getConfig
 * Get application options
 * - Returns an instance of module.Config
 */
contextBridge.exposeInMainWorld('getConfig', () =>{
	return ipcRenderer.sendSync('get-config');
});

/**
 * - openFile
 * Show an open file dialog
 * - options: see https://www.electronjs.org/docs/api/dialog#dialogshowopendialogsyncbrowserwindow-options
 * - Returns an array of path names
 */
contextBridge.exposeInMainWorld('openFile', (options) =>{ 
	return ipcRenderer.sendSync('open-file', options);
});

/**
 * - saveFile
 * Show a save file dialog
 * - options: see https://www.electronjs.org/docs/api/dialog#dialogshowsavedialogsyncbrowserwindow-options
 * - Returns a path name
 */
contextBridge.exposeInMainWorld('saveFile', (options) => {
	return ipcRenderer.sendSync('save-file', options);
});

/**
 * - changeExt
 * Replace file extension
 * - src: complete original file name
 * - newExt: new file extension
 * - Returns the complete path with new extension
 */
contextBridge.exposeInMainWorld('changeExt', (src, newExt) =>{
	let parsed = path.parse(src);
	return path.format({ dir: parsed.dir, name: parsed.name, ext: newExt });
});

/**
 * - fileExists
 * Check if a file exists
 * - fileName: complete path to file
 * - Returns file existence indicator
 */
contextBridge.exposeInMainWorld('fileExists', (fileName) => {
	return fs.existsSync(fileName);
});

contextBridge.exposeInMainWorld('dirExists', (path) => {
	let ret = false;
	try {
		let dir = fs.opendirSync(path);
		dir.closeSync();
		ret = true;
	}
	catch (e) {}
	return ret;
});

/**
 * - parentFolder
 * Get the directory portion of a path
 * - pathName: path
 * - Returns directory path
 */
contextBridge.exposeInMainWorld('parentFolder', (pathName) => {
	let parsed = path.parse(pathName);
	return parsed.dir;
});

/**
 * - updateConfig
 * Update current application options
 * - cfg: instance of module.Config
 */
contextBridge.exposeInMainWorld('updateConfig', (cfg) => {
	ipcRenderer.sendSync('update-config', cfg);
});

/**
 * - showMessage
 * Show message box dialog
 * - options: see https://www.electronjs.org/docs/api/dialog#dialogshowmessageboxbrowserwindow-options
 */
contextBridge.exposeInMainWorld('showMessage', (options) => {
	ipcRenderer.sendSync('show-message', options);
});

/**
 * - createTempFile
 * Creates a temporary file
 * Returns a file handle (where handle > 0)
 */
contextBridge.exposeInMainWorld('createTempFile', () => {
	return ipcRenderer.sendSync('create-tmp-file');
});

/**
 * - writeFile
 * Writes contents to temporary file
 * - data: write data object, where:
 *		handle: temporary file handle
 *		contents: the contents to write
 * Returns true if succeded; otherwise, false.
 */
 contextBridge.exposeInMainWorld('writeFile', (data) => {
	return ipcRenderer.sendSync('write-file', (data));
});


/**
 * - openURI
 * Opens a temporary file using platform default application
 * - handle: temporary file handle
 * Returns true if handle is valid; otherwise, false.
 */
 contextBridge.exposeInMainWorld('openURI', (handle) => {
	return ipcRenderer.sendSync('open-uri', handle);
});

/**
 * - releaseTempFile
 * Releases created temporary file
 * - handle: temporary file handle
 * Returns true if handle is valid; otherwise, false.
 */
 contextBridge.exposeInMainWorld('releaseTempFile', (handle) => {
	return ipcRenderer.sendSync('release-tmp-file', handle);
});


/** * * * * * * * * * * * * * * *
 * Calls to native code
 *  * * * * * * * * * * * * * * */

/**
 * - getCertificates
 * Get available signing certificates of the current user. Only 
 * personal certificates within their validity date are returned.
 * - Returns a (possibly empty) array of the certificate common names
 */
contextBridge.exposeInMainWorld('getCertificates', () => {
	return ipcRenderer.sendSync('get-certificates');
});

/**
 * - sign
 * Sign a document
 * - data: instance of module.SigningData
 * - Returns instance of module.OperationResult
 */
 contextBridge.exposeInMainWorld('sign', (data) => {
	return ipcRenderer.sendSync('sign-document', data);
});

/**
 * - parseCMSSignedData
 * Parse a CMS Signed Data envelope
 * - data: instance of module.VerifyData
 * Returns a state handle for further operations
 */
contextBridge.exposeInMainWorld('parseCMSSignedData', (data) => {
	return ipcRenderer.sendSync('parse-signed-data', data);
});

/**
 * - verifySignature
 * Verifies cryptographic signature of a parsed CS Signed Data document
 *- handle: state handle returned by parse-signed-data message
 * Returns true for successful verification; otherwise, false.
 */
contextBridge.exposeInMainWorld('verifySignature', (handle) => {
	return ipcRenderer.sendSync('verify-signature', handle);
});

/**
 * - getSigningTime
 * Returns signing time signed attribute value
 * - handle: state handle returned by parse-signed-data message
 * Returns a string in the form yyyy-MM-ddThh:mm:ss.sssZ or null if the attribute is not presents
 */
 contextBridge.exposeInMainWorld('getSigningTime', (handle) => {
	return ipcRenderer.sendSync('get-signing-time', handle);
});

/**
 * - verifySigningCertificate
 * Checks if signing certificate is trusted. The certificate must be embedded in the envelope.
 * - handle: state handle returned by parse-signed-data message
 * Returns true for successful verification; otherwise, false. A signing certificate
 * must be associated with a complete and trusted certificate chain in the system repository to be trusted
 */
contextBridge.exposeInMainWorld('verifySigningCertificate', (handle) => {
	return ipcRenderer.sendSync('verfify-signing-certificate', handle);
});

/**
 * - getSignerIdentifier
 * Gets CMS Signer Info signer identifier field
 * - handle: state handle returned by parse-signed-data message
 * Returns an instance of module.SignerIdentifier
 */
 contextBridge.exposeInMainWorld('getSignerIdentifier', (handle) => {
	return ipcRenderer.sendSync('get-signer-identifier', handle);
});

/**
 * - getContentInfo
 * Gets the encapsulated content info, if it is attached
 * - handle: state handle returned by parse-signed-data message
 * Returns the contents as an Uint8Array
 */
contextBridge.exposeInMainWorld('getContentInfo', (handle) => {
	return ipcRenderer.sendSync('get-content-info', handle);
});

/**
 * - releaseCMSHandle
 * Releases CMS Signed Data parsed file handle
 *	handle: state handle returned by parse-signed-data message
 * Returns 0, if succeeded
 */
 contextBridge.exposeInMainWorld('releaseCMSHandle', (handle) => {
	return ipcRenderer.sendSync('release-cms-handle', handle);
});

/**
 * - retreatCall
 * Resets flag of window opened, to avoid showing a new panel while another is still opened
 */
 let rendererHasWindowOpen = false;
 contextBridge.exposeInMainWorld('retreatCall', () => {
	 rendererHasWindowOpen = false;
 });
 
 

/** * * * * * * * * * * * * * * *
 * Commands from main process
 *  * * * * * * * * * * * * * * */

/**
 * - open-sign
 * Show the wizard to document signature
 */
ipcRenderer.on('open-sign', () => {
	if (!rendererHasWindowOpen)
	{
		document.getElementById('sign-div').style = 'display: block';
		document.dispatchEvent(new CustomEvent('sign-wizard-open'));
		rendererHasWindowOpen = true;
	}
});

/**
 * - open-verify
 * Show signed document validation panel
 */
ipcRenderer.on('open-verify', () => {
	if (!rendererHasWindowOpen)
	{
		document.getElementById('verify-div').style = 'display: block';
		document.dispatchEvent(new CustomEvent('verify-loaded'));
		rendererHasWindowOpen = true;
	}
});

/**
 * - open-options
 * Show options panel
 */
ipcRenderer.on('open-options', () => {
	if (!rendererHasWindowOpen)
	{
		document.getElementById('options-div').style = 'display: block';
		document.dispatchEvent(new CustomEvent('options-open'));
		rendererHasWindowOpen = true;
	}
});
