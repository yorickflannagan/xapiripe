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
 * See https://bitbucket.org/yakoana/xapiripe/src/master/signthing
 * main.js - Electron main process
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

const { app, BrowserWindow, Menu, shell, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');
const { Config, SigningData, OperationResult, VerifyData, TempFile } = require('./module');
const {
	XPEListCertificates,
	XPEBasicSign,
	XPEParseCMSSignedData,
	XPEVerifySignature,
	XPEGetSigningTime,
	XPEVerifyCertificate,
	XPEGetSignerIdentifier,
	XPEGetEncapContent,
	XPEReleaseCMSSignedData
} = require('./native');
const tmp = require('tmp');


/** * * * * * * * * * * * *
 * UI
 *  * *  * * * * * * * * */
const optionsFile = path.join(app.getAppPath(), 'options.json');
const template = [
	{
		label: 'Arquivo',
		submenu: [
			{ label: 'Assinar...', click: () => {
				mainWindow.webContents.send('open-sign');
			}},
			{ label: 'Verificar...', click: () => {
				mainWindow.webContents.send('open-verify');
			}},
			{ 'type': 'separator' },
			{ label: 'Sair', role: 'quit'} // TODO: Emitir alerta para saída do serviço
		]
	},
	{
		label: 'Ferramentas',
		submenu: [
			{ label: 'Requisitar certificado...' },
			{ label: 'Instalar certificado...' },
			{ 'type': 'separator' },
			{ label: 'Opções...', click: () => {
				mainWindow.webContents.send('open-options');
			}}
		]
	},
	{
		label: 'Ajuda',
		submenu: [
			{ label: 'Licença', click: async () => {
				shell.openExternal('https://opensource.org/licenses/LGPL-3.0');
			}},
			{ label: 'Política de Privacidade', click: async () => {
				shell.openExternal('https://bitbucket.org/yakoana/xapiripe/src/master/signthing/privacy.md');
			}},
			{ 'type': 'separator' },
			{ label: 'Sobre', click: () => {
				const abt = new BrowserWindow({
					width: 400,
					height: 300,
					resizable: false,
					modal: true,
					webPreferences: { preload: path.join(__dirname, 'about.js') }
				});
				abt.setMenu(null);
				abt.loadFile(path.join(__dirname, 'ui', 'about.html'));
			}}
		]
	}
];
let mainWindow = null;		// Main window
let cfg = null;				// Application customizations
let tempFiles = new Map();	// Temporary files (to view contents)
let service = null;			// Hekura child process
tmp.setGracefulCleanup();

app.on('ready', () => {
	try { cfg = Config.load(optionsFile); }
	catch (err)
	{
		dialog.showMessageBoxSync(mainWindow, {
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Erro ao carregar a configuração',
			detail: 'A aplicação assumirá seus valores padronizados'
		});
		cfg = new Config();
	}

	let logArg = '--log='.concat(JSON.stringify(cfg.logOptions));
	let svrArg = '--server='.concat(JSON.stringify(cfg.serverOptions));
	service = cp.fork(`${__dirname}/service.js`, [ logArg, svrArg ], { cwd: __dirname, detached: false });
	service.on('message', (message) => {
		// TODO:
	});

	const menu = Menu.buildFromTemplate(template);
	mainWindow = new BrowserWindow({
		minWidth: 800,
		minHeight: 640,
		icon: path.join(__dirname, 'ui', 'res', 'signature.png'),
		webPreferences: { preload: path.join(__dirname, 'preload.js')}
	});
	mainWindow.setMenu(menu);
	mainWindow.webContents.loadFile(path.join(__dirname, 'ui', 'index.html'));
	mainWindow.webContents.openDevTools();
	mainWindow.once('ready-to-show', () => { mainWindow.show(); });
});

app.on('before-quit', () => {
	try { cfg.store(optionsFile); }
	catch (err)
	{
		dialog.showMessageBoxSync(mainWindow, {
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Erro ao salvar a configuração',
			detail: 'Os valores correntes serão perdidos'
		});
	}
	if (service) service.send({ signal: 'stop-service' });
});


/** * * * * * * * * * * * * * * *
 * Services provided to renderer
 *  * * * * * * * * * * * * * * */

/**
 * Exibe diálogo para tomada de decisão
 */
ipcMain.on('ask-dialog', (evt, param) => {
	dialog.showMessageBox({
		message: param.message,
		type: 'question',
		buttons: [ 'Cancelar', 'OK' ],
		defaultId: 0,
		title : param.title,
		checkboxLabel: 'Não perguntar novamente'
	})
	.then((response, checkboxChecked) => {
		evt.returnValue = {
			choice: response,
			dontAsk: checkboxChecked
		}
	})
	.catch(() => {
		evt.returnValue = {
			choice: 0,
			dontAsk: false
		}
	});
});

/**
 * Application version
 */
ipcMain.on('get-version',  (evt) => { evt.returnValue = app.getVersion(); });

/**
 * Load user signing certificates
 */
ipcMain.on('get-certificates', (evt) => {

	let certs;
	try { certs = XPEListCertificates(); }
	catch (err)
	{
		dialog.showMessageBoxSync(mainWindow, {
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Erro ao carregar os certificados',
			detail: 'Impossível assinar quaisquer documentos'
		});
	}
	evt.returnValue = certs;
});

/**
 * Provide application options
 */
ipcMain.on('get-config', (evt) => { evt.returnValue = cfg; });

/**
 * Open file dialog
 * 	options: see https://www.electronjs.org/docs/api/dialog#dialogshowopendialogsyncbrowserwindow-options
 */
ipcMain.on('open-file', (evt, options) =>{ evt.returnValue = dialog.showOpenDialogSync(mainWindow, options); });

/**
 * Save file dialog
 *	options: see https://www.electronjs.org/docs/api/dialog#dialogshowsavedialogsyncbrowserwindow-options
 */
ipcMain.on('save-file', (evt, options) => { evt.returnValue = dialog.showSaveDialogSync(mainWindow, options); });

/**
 * Update current application options
 *	newCfg: instance of module.Config
 */
ipcMain.on('update-config', (evt, newCfg) => {
	cfg = Object.setPrototypeOf(newCfg, Config.prototype); 
	evt.returnValue = true;
});

/**
 * Message box dialog
 *	options: see https://www.electronjs.org/docs/api/dialog#dialogshowmessageboxbrowserwindow-options
 */
 ipcMain.on('show-message', (evt, options) => { 
	dialog.showMessageBox(mainWindow, options);
	evt.returnValue = true;
});

/**
 * Signs a file with selected certificate
 *	options: instance of module.SigningData
 * Returns a CMS Signed Data envelope
 *
 */
ipcMain.on('sign-document', (evt, options) => {
	let args = Object.setPrototypeOf(options, SigningData.prototype);
	let ret;
	try
	{
		let buff = fs.readFileSync(options.signedContents);
		let contents = new Uint8Array(buff.buffer);
		let pkcs7 = XPEBasicSign(options.signingCert, args.algorithmAsNumber(), options.attachContents ? 1 : 0, contents);
		fs.writeFileSync(options.signedEnvelope, pkcs7);
		ret = new OperationResult(true, 'Operação de assinatura digital bem sucedida', 'O envelope assinado foi salvo em ' + options.signedEnvelope);
	}
	catch (err) { ret = new OperationResult(false, 'Falha na operação de assinatura digital', err.message ? err.message : err); }
	evt.returnValue = ret;
});

/**
 * Parses specified CMS Signed Data envelope
 *	data: instance of modules.VerifyData
 * Returns a state handle for further operations
 */
ipcMain.on('parse-signed-data', (evt, data) => {
	let arg = Object.setPrototypeOf(data, VerifyData.prototype);
	let ret = 0;
	try
	{
		let envelopeBuff = arg.loadEnvelope();
		let contentsBuff = null;
		if (data.contents) arg.loadContents();
		ret = XPEParseCMSSignedData(envelopeBuff, contentsBuff);
	}
	catch (err) { ret = new OperationResult(false, 'Falha no carregamento de documento CMS assinado', err.message ? err.message : err); }
	evt.returnValue = ret;
});

/**
 * Verifies cryptographic signature of a parsed CS Signed Data document
 *	handle: state handle returned by parse-signed-data message
 * Returns true for successful verification; otherwise, false.
 */
ipcMain.on('verify-signature', (evt, handle) => {
	evt.returnValue = XPEVerifySignature(handle);
});

/**
 * Returns signing time signed attribute value
 *	handle: state handle returned by parse-signed-data message
 * Returns a string in the form yyyy-MM-ddThh:mm:ss.sssZ or null if the attribute is not presents
 */
ipcMain.on('get-signing-time', (evt, handle) => {
	evt.returnValue = XPEGetSigningTime(handle);
});

/**
 * Checks if signing certificate is trusted. The certificate must be embedded in the envelope.
 *	handle: state handle returned by parse-signed-data message
 * Returns true for successful verification; otherwise, false. A signing certificate
 * must be associated with a complete and trusted certificate chain in the system repository to be trusted
 */
ipcMain.on('verfify-signing-certificate', (evt, handle) => {
	evt.returnValue = XPEVerifyCertificate(handle);
});

/**
 * Gets CMS Signer Info signer identifier field
 *	handle: state handle returned by parse-signed-data message
 * Returns an instance of module.SignerIdentifier
 */
ipcMain.on('get-signer-identifier', (evt, handle) => {
	evt.returnValue = XPEGetSignerIdentifier(handle);
});

/**
 * Gets the encapsulated content info, if it is attached
 *	handle: state handle returned by parse-signed-data message
 * Returns the contents as an Uint8Array
 */
ipcMain.on('get-content-info', (evt, handle) => {
	evt.returnValue = XPEGetEncapContent(handle);
});

/**
 * Releases CMS Signed Data parsed file handle
 *	handle: state handle returned by parse-signed-data message
 * Returns 0, if succeeded
 */
ipcMain.on('release-cms-handle', (evt, handle) => {
	evt.returnValue = XPEReleaseCMSSignedData(handle);
});

/**
 * Creates a temporary file
 * Returns a file handle (where handle > 0)
 */
ipcMain.on('create-tmp-file', (evt) => {
	let env = new TempFile(tmp.fileSync());
	tempFiles.set(env.handle, env);
	evt.returnValue = env.handle;
});

/**
 * Writes contents to temporary file
 *	data: write data object, where:
 *		handle: temporary file handle
 *		contents: the contents to write
 * Returns true if succeded; otherwise, false.
 */
ipcMain.on('write-file', (evt, data) => {
	let ret = false;
	try {
		let tf = tempFiles.get(data.handle);
		if (!tf) throw 'Descritor de arquivo temporário inválido';
		fs.writeFileSync(tf.tmp.fd, data.contents);
		ret = true;
	}
	catch (err) {
		dialog.showMessageBoxSync(mainWindow, {
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Erro ao salvar o arquivo',
			detail: 'Impossível escrever no arquivo ' + handle.name
		});
	}
	evt.returnValue = ret;
});

/**
 * Opens a temporary file using platform default application
 *	handle: temporary file handle
 * Returns true if handle is valid; otherwise, false.
 */
ipcMain.on('open-uri', (evt, handle) => {
	let tf = tempFiles.get(handle);
	let ret = tf ? true : false;
	if (tf) shell.openExternal('file://' + tf.tmp.name);
	evt.returnValue = ret;
});

/**
 * Releases created temporary file
 *	handle: temporary file handle
 * Returns true if handle is valid; otherwise, false.
 */
ipcMain.on('release-tmp-file', (evt, handle) => {
	let tf = tempFiles.get(handle);
	let ret = tf ? true : false;
	if (tf)
	{
		tf.tmp.removeCallback();
		tempFiles.delete(handle);
	}
	evt.returnValue = ret;
});
