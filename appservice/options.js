/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020-2022 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 *
 * Xapiripe - Standalone Hekura service
 * See https://bitbucket.org/yakoana/xapiripe/src/master/appservice
 * options.js - Options dialog renderer
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
const crypto = require('crypto');
const fs = require('fs');

/**
 * Representação de uma origem (confiável) na interface
 */
class Origins extends Set {
	constructor(ask) {
		super();
		this.warning = ask;
	}
	remove(id) {
		this.forEach((item) => {
			if (item.id === id) this.delete(item);
		});
	}
}
/**
 * Instância de Origins (as origens representadas na interface)
 */
let optOrigins = null;
/**
 * Indicador de janela já inicializada (proteção contra múltiplas instâncias de um listener)
 */
let optWindowOpen = false;

/**
 * Alterna entre os diferentes painéis de opções
 * @param { string } tab: nome do painel a ser exibido
 */
function showTab(tab) {
	let i;
	let x = document.getElementsByClassName("tab");
	for (i = 0; i < x.length; i++) x[i].style.display = "none";  
	document.getElementById(tab).style.display = "block";
}

/**
 * Cria um elemento de interface para representar uma origem confiável
 * @param { Origin } trustedOrigin: nova origem a ser adicionada à interface (ver module.js)
 * @returns uma instância de um HTMLLIElement
 */
function newTrustedOriginElement(trustedOrigin) {
	let span = document.createElement('span');
	span.setAttribute('class', 'w3-button w3-transparent w3-display-right signal');
	span.innerHTML = '&times;';
	span.addEventListener('click', () => {
		let doIt = true;
		if (optOrigins.warning) {
			let answer = ipcRenderer.sendSync('ask-dialog', {
				message: 'Essa operação removerá permanentemente a origem selecionada. Deseja prosseguir?',
				title: 'Remover origem confiável'
			});
			doIt = answer.response != 0;
			optOrigins.warning = !answer.checkboxChecked;
		}
		if (doIt) {
			let item = document.getElementById(trustedOrigin.id);
			item.parentNode.removeChild(item);
			optOrigins.remove(trustedOrigin.id);
		}
	});
	let item = document.createElement('li');
	item.setAttribute('id', trustedOrigin.id);
	item.setAttribute('class', 'w3-display-container');

	let content = document.createTextNode(trustedOrigin.origin);
	item.insertBefore(content, item.lastChild);
	item.insertBefore(span, item.lastChild);
	return item;
}

function hashObject(ob) {
	let hash = crypto.createHash('sha256');
	hash.update(ob.serverOptions.trustedOrigins.warning.toString());
	for (let i = 0; i < ob.serverOptions.trustedOrigins.origins.length; i++) {
		hash.update(ob.serverOptions.trustedOrigins.origins[i].origin);
	}
	hash.update(ob.logOptions.path)
		.update(ob.logOptions.fname)
		.update(ob.logOptions.maxSize.toString())
		.update(ob.logOptions.rotate.toString())
		.update(ob.logOptions.level.toString());
	return hash.digest();
}

window.addEventListener('DOMContentLoaded', () => {
	try {

		// Elementos de UI
		const btnTrustedOrigins = document.getElementById('btnTrustedOrigins');
		const btnLog = document.getElementById('btnLog');
		const trustedList = document.getElementById('trustedList');
		const inputTrusted = document.getElementById('inputTrusted');
		const btnAddTrusted = document.getElementById('btnAddTrusted');
		
		const inputDir = document.getElementById('inputDir');
		const btnSource = document.getElementById('btnSource');
		const inputFile = document.getElementById('inputFile');
		const logLevel = document.getElementById('logLevel');
		const inputSize = document.getElementById('inputSize');
		const inputRotate = document.getElementById('inputRotate');

		const btnCancel = document.getElementById('btnCancel');
		const btnSave = document.getElementById('btnSave');

		if (
			!btnTrustedOrigins || !btnLog ||
			!trustedList || !inputTrusted || !btnAddTrusted ||
			!inputDir || !btnSource || !inputFile ||
			!logLevel || !inputSize || !inputRotate ||
			!btnCancel || !btnSave
		) 	throw new Error('Um dos elementos da interface não foi encontrado');

		// Recupera opções salvas
		const cfg = ipcRenderer.sendSync('get-config');
		let originalHash = hashObject(cfg);
		optOrigins = new Origins(cfg.serverOptions.trustedOrigins.warning);
		cfg.serverOptions.trustedOrigins.origins.forEach((item) => {
			optOrigins.add(item);
			let li = newTrustedOriginElement(item);
			trustedList.appendChild(li);
		});

		inputDir.value = cfg.logOptions.path;
		inputFile.value = cfg.logOptions.fname;
		logLevel.selectedIndex = cfg.logOptions.level;
		inputSize.value = cfg.logOptions.maxSize;
		inputRotate.value = cfg.logOptions.rotate;

		// Navegação nas tabs
		if (!optWindowOpen) btnTrustedOrigins.addEventListener('click', () => { showTab('trustedOrigins'); });
		if (!optWindowOpen) btnLog.addEventListener('click', () => { showTab('log'); });

		// Adiciona uma origem confiável
		if (!optWindowOpen)
		btnAddTrusted.addEventListener('click', () => {
			let pattern = /^(http|https):\/\/(([a-zA-Z0-9$\-_.+!*'(),;:&=]|%[0-9a-fA-F]{2})+@)?(((25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|localhost|([a-zA-Z0-9]+\.)+([a-zA-Z]{2,}))(:[0-9]+)?(\/(([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*)*)?(\?([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?(\#([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?)?$/;
			let uri = inputTrusted.value;
			if (!uri.match(pattern)) {
				ipcRenderer.sendSync('show-message', {
					message: 'O valor informado não é uma URL válida',
					type: 'error',
					title: 'Adicionar origem confiável'
				});
				return;
			}
			let trustedOrigin = { origin: uri, id: crypto.randomUUID() };
			let li = newTrustedOriginElement(trustedOrigin);
			trustedList.appendChild(li);
			inputTrusted.value = '';
			optOrigins.add(trustedOrigin);
		});

		// Seleciona um novo diretório de log
		if (!optWindowOpen)
		btnSource.addEventListener('click', () => {
			let choice = ipcRenderer.sendSync('open-file', {
				title: 'Selecionar diretório de log',
				defaultPath: __dirname,
				properties: [ 'openDirectory' ]
			});
			if (typeof choice !== undefined) { inputDir.value = choice[0]; }
		});

		// Cancelar/salvar opções
		if (!optWindowOpen)
		btnCancel.addEventListener('click', () => { window.close(); });
		if (!optWindowOpen)
		btnSave.addEventListener('click', () => {
			
			// Valida entrada de dados
			let dirExists = false;
			let logDir = inputDir.value;
			try {
				let dir = fs.opendirSync(logDir);
				dir.closeSync();
				dirExists = true;
			}
			catch (e) {}
			if (!dirExists) {
				ipcRenderer.sendSync('show-message', {
					message: 'O diretório selecionado não existe',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O diretório selecionado para os arquivos de log deve existir e você deve ter permissão de escrita nele'
				});
				return;
			}
			let pattern = inputFile.value;
			if (!pattern.includes('-n')) {
				ipcRenderer.sendSync('show-message', {
					message: 'Padrão de arquivo de log inválido',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O padrão para o nome do arquivo de log deve conter a string -n'
				});
				return;
			}
			let maxSize = Number.parseInt(inputSize.value);
			if (isNaN(maxSize) || maxSize > 65536) {
				ipcRenderer.sendSync('show-message', {
					message: 'Tamanho de arquivo inválido',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O campo Tamanho máximo do arquivo deve conter um numérico menor ou igual a 65536 KB'
				});
				return;
			}
			let rotate = Number.parseInt(inputRotate.value);
			if (isNaN(rotate) || rotate > 32) {
				ipcRenderer.sendSync('show-message', {
					message: 'Quantidade de arquivos inválida',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O campo Quantidade máxima de arquivos deve conter um numérico menor ou igual a 32'
				});
				return;
			}

			// Atualiza a configuração
			cfg.serverOptions.trustedOrigins.warning = optOrigins.warning;
			cfg.serverOptions.trustedOrigins.origins = [];
			let it = optOrigins.values();
			let next = it.next();
			while (!next.done) {
				cfg.serverOptions.trustedOrigins.origins.push(next.value);
				next = it.next();
			}
			cfg.logOptions.path = logDir;
			cfg.logOptions.fname = pattern;
			cfg.logOptions.maxSize = maxSize;
			cfg.logOptions.rotate = rotate;
			cfg.logOptions.level = logLevel.selectedIndex;

			let newHash = hashObject(cfg);
			if (Buffer.compare(originalHash, newHash) != 0) {
				let restart = cfg.app.restartOnChange;
				if (cfg.app.askToRestart) {
					let answer = ipcRenderer.sendSync('ask-dialog', {
						message: 'Para que as alterações tenha efeito, o serviço precisa reiniciar. Deseja fazer isso agora?',
						title: 'Salvar opções'
					});
					cfg.app.askToRestart = !answer.checkboxChecked;
					if (!cfg.app.askToRestart) cfg.app.restartOnChange = answer.response != 0;
					restart = answer.response != 0;
				}
				ipcRenderer.sendSync('update-config', cfg);
				if (restart) ipcRenderer.send('relaunch-app');
			}
			window.close();
		});
	}
	catch (err) {
		ipcRenderer.sendSync('show-message', {
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Erro ao carregar a página',
			detail: 'A aplicação não está funcionando apropriadamente'
		});
	}
	optWindowOpen = true;
});