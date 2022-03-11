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
 * sign.js - sign.html behaviour
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
let optOrigins = null;
let optWindowOpen = false;

function showTab(tab) {
	const iframe = document.getElementById('options-div').contentWindow;
	let i;
	let x = iframe.document.getElementsByClassName("tab");
	for (i = 0; i < x.length; i++) x[i].style.display = "none";  
	iframe.document.getElementById(tab).style.display = "block";
}
function newTrustedOriginElement(trustedOrigin) {
	const iframe = document.getElementById('options-div').contentWindow;
	let span = iframe.document.createElement('span');
	span.setAttribute('class', 'w3-button w3-transparent w3-display-right signal');
	span.innerHTML = '&times;';
	span.addEventListener('click', () => {
		let doIt = true;
		if (optOrigins.warning) {
			let answer = window.askDialog({
				message: 'Essa operação removerá permanentemente a origem selecionada. Deseja prosseguir?',
				title: 'Remover origem confiável'
			});
			doIt = answer.choice.response != 0;
			optOrigins.warning = !answer.choice.checkboxChecked;
		}
		if (doIt) {
			let item = iframe.document.getElementById(trustedOrigin.id);
			item.parentNode.removeChild(item);
			optOrigins.remove(trustedOrigin.id);
		}
	});
	let item = iframe.document.createElement('li');
	item.setAttribute('id', trustedOrigin.id);
	item.setAttribute('class', 'w3-display-container');

	let content = iframe.document.createTextNode(trustedOrigin.origin);
	item.insertBefore(content, item.lastChild);
	item.insertBefore(span, item.lastChild);
	return item;
}
function randomUUID() {
	return (
		[1e7]+-1e3+-4e3+-8e3+-1e11).replace(
			/[018]/g,
			c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4
		).toString(16)
	);
}
  
document.addEventListener('options-open', () => {
	try {

		// Elementos de UI
		const iframe = document.getElementById('options-div').contentWindow;
		const btnTrustedOrigins = iframe.document.getElementById('btnTrustedOrigins');
		const btnLog = iframe.document.getElementById('btnLog');
		const btnAdvanced = iframe.document.getElementById('btnAdvanced');
		const trustedList = iframe.document.getElementById('trustedList');
		const inputTrusted = iframe.document.getElementById('inputTrusted');
		const btnAddTrusted = iframe.document.getElementById('btnAddTrusted');
		
		const inputDir = iframe.document.getElementById('inputDir');
		const btnSource = iframe.document.getElementById('btnSource');
		const inputFile = iframe.document.getElementById('inputFile');
		const logLevel = iframe.document.getElementById('logLevel');
		const inputSize = iframe.document.getElementById('inputSize');
		const inputRotate = iframe.document.getElementById('inputRotate');

		const inputPort = iframe.document.getElementById('inputPort');
		const inputAge = iframe.document.getElementById('inputAge');

		const btnCancel = iframe.document.getElementById('btnCancel');
		const btnSave = iframe.document.getElementById('btnSave');

		if (
			!btnTrustedOrigins || !btnLog || !btnAdvanced ||
			!trustedList || !inputTrusted || !btnAddTrusted ||
			!inputDir || !btnSource || !inputFile ||
			!logLevel || !inputSize || !inputRotate ||
			!inputPort || !inputAge ||
			!btnCancel || !btnSave
		) 	throw new Error('Um dos elementos da interface não foi encontrado');

		// Recupera opções salvas
		const cfg = window.getConfig();
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
		inputPort.value = cfg.serverOptions.port;
		inputAge.value = cfg.serverOptions.maxAge;


		// Navegação nas tabs
		if (!optWindowOpen) btnTrustedOrigins.addEventListener('click', () => { showTab('trustedOrigins'); });
		if (!optWindowOpen) btnLog.addEventListener('click', () => { showTab('log'); });
		if (!optWindowOpen) btnAdvanced.addEventListener('click', () => { showTab('advanced'); });

		// Adiciona uma origem confiável
		if (!optWindowOpen)
		btnAddTrusted.addEventListener('click', () => {
			let pattern = /^(http|https):\/\/(([a-zA-Z0-9$\-_.+!*'(),;:&=]|%[0-9a-fA-F]{2})+@)?(((25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|localhost|([a-zA-Z0-9]+\.)+([a-zA-Z]{2,}))(:[0-9]+)?(\/(([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*)*)?(\?([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?(\#([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?)?$/;
			let uri = inputTrusted.value;
			if (!uri.match(pattern)) {
				window.showMessage({
					message: 'O valor informado não é uma URL válida',
					type: 'error',
					title: 'Adicionar origem confiável'
				});
				return;
			}
			let trustedOrigin = { origin: uri, id: randomUUID() };
			let li = newTrustedOriginElement(trustedOrigin);
			trustedList.appendChild(li);
			inputTrusted.value = '';
			optOrigins.add(trustedOrigin);
		});

		// Seleciona um novo diretório de log
		if (!optWindowOpen)
		btnSource.addEventListener('click', () => {
			let choice = window.openFile({
				title: 'Selecionar diretório de log',
				defaultPath: cfg.lastFolder,
				properties: 'openDirectory'
			});
			if (typeof choice !== undefined) {
				inputDir.value = choice[0];
				cfg.lastFolder = choice[0];
			}
		});

		// Cancelar/salvar opções
		if (!optWindowOpen)
		btnCancel.addEventListener('click', () => {
			document.getElementById('options-div').style = 'display: none'
			window.retreatCall();
		});
		if (!optWindowOpen)
		btnSave.addEventListener('click', () => {
			// Valida entrada de dados
			let dir = inputDir.value;
			if (!window.dirExists(dir)) {
				window.showMessage({
					message: 'O diretório selecionado não existe',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O diretório selecionado para os arquivos de log deve existir e você deve ter permissão de escrita nele'
				});
				return;
			}
			let pattern = inputFile.value;
			if (!pattern.includes('-n')) {
				window.showMessage({
					message: 'Padrão de arquivo de log inválido',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O padrão para o nome do arquivo de log deve conter a string -n'
				});
				return;
			}
			let maxSize = Number.parseInt(inputSize.value);
			if (isNaN(maxSize) || maxSize > 65536) {
				window.showMessage({
					message: 'Tamanho de arquivo inválido',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O campo Tamanho máximo do arquivo deve conter um numérico menor ou igual a 65536 KB'
				});
				return;
			}
			let rotate = Number.parseInt(inputRotate.value);
			if (isNaN(rotate) || rotate > 32) {
				window.showMessage({
					message: 'Quantidade de arquivos inválida',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O campo Quantidade máxima de arquivos deve conter um numérico menor ou igual a 32'
				});
				return;
			}
			let port = Number.parseInt(inputPort.value);
			if (isNaN(port) || port < 1024 || port > 65535) {
				window.showMessage({
					message: 'Porta inválida',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O campo Porta deve conter um valor numérico entre 1024 e 65535'
				});
				return;
			}
			let maxAge = Number.parseInt(inputAge.value);
			if (isNaN(maxAge)) {
				window.showMessage({
					message: 'Tempo de cache inválido',
					type: 'error',
					title: 'Dados inválidos',
					detail: 'O campo Cache do preflight CORS deve ser numérico'
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
			cfg.serverOptions.port = port;
			cfg.serverOptions.maxAge = maxAge;
			cfg.logOptions.path = dir;
			cfg.logOptions.fname = pattern;
			cfg.logOptions.maxSize = maxSize;
			cfg.logOptions.rotate = rotate;
			cfg.logOptions.level = logLevel.selectedIndex;
			window.updateConfig(cfg);

			document.getElementById('options-div').style = 'display: none'
			window.retreatCall();
		});
	}
	catch (err) {
		window.showMessage({
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Erro ao carregar a página',
			detail: 'A aplicação não está funcionando apropriadamente'
		});
	}
	optWindowOpen = true;
});