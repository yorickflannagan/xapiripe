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
 * about.js - about.html behaviour
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
const { ipcRenderer } = require('electron');

window.addEventListener('DOMContentLoaded', () => {
	document.getElementById('version').innerText = ipcRenderer.sendSync('get-version');
	document.getElementById('electron').innerText = process.versions.electron;
	document.getElementById('chrome').innerText = process.versions.chrome;
	document.getElementById('node').innerText = process.versions.node;
	document.getElementById('v8').innerText = process.versions.v8;
	document.getElementById('os').innerText = process.platform + ' - ' + process.arch;
	
	document.getElementById('close').addEventListener('click', () => { window.close(); });
});
