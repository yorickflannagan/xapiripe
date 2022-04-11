/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020-2022 The Crypthing Initiative
 * Author: yorick.flannagan@gmail.com
 *
 * Xapiripe - Standalone Hekura service
 * See https://bitbucket.org/yakoana/xapiripe/src/master/appservice
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

const { app, BrowserWindow, Menu, Tray, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const cp = require('child_process');

const { Config, Message, WarnResponse, UserQuestion, DelayedPromise } = require('./module');
const { sprintf } = require('wanhamou');



const OPTIONS = path.join(__dirname, 'runtime', 'options.json');
const ICO = path.join(__dirname, 'res', 'signature-32x32.ico');
const IFACE = path.join(__dirname, 'res', 'options.html');
const LICENCE = 'https://opensource.org/licenses/LGPL-3.0';
const HELP = 'file:///' + path.join(__dirname, 'res', 'help.html');
const APP_TITLE = 'Serviço Hekura';
const OPERATIONS = [ 'enumerateDevices', 'generateCSR', 'installCertificates', 'enumerateCertificates', 'sign', 'verify' ];
const ACTIONS = [
	'enumerar dispositivos criptográficos presentes',
	'assinar requisição de certificado digital',
	'instalar certificado assinado',
	'enumerar certificados de assinatura instalados',
	'assinar o documento a seguir',
	'verificar documento assinado'
];
const contextMenu = [
	{ label: 'Opções do serviço...', click: () => { optionsWindow.show(); }},
	{ 'type': 'separator' },
	{ label: 'Ajuda', click: () => { shell.openExternal(HELP)}},
	{ label: 'Licença', click: () => { shell.openExternal(LICENCE)}},
	{ label: 'Sobre...', click: () => {
		let contents = 'Versão: '.concat(app.getVersion()).concat('\n')
			.concat('Electron: ').concat(process.versions.electron).concat('\n')
			.concat('Chrome: ').concat(process.versions.chrome).concat('\n')
			.concat('Node.js: ').concat(process.versions.node).concat('\n');
		tray.displayBalloon({
			iconType: 'info',
			title: 'Sobre o ' + APP_TITLE,
			content: contents,
			noSound: true
		});
	}},
	{ 'type': 'separator' },
	{ label: 'Sair', click: () => { app.quit(); }}
];
const optionsMenu = [
	{ label: 'Fechar', click: () => { optionsWindow.close(); }}
];

/**
 * Interface com o usuário para escolha das opções de inicialização da aplicação. Em particular, permite que a contramedida (ii), 
 * definida no documento Modelo de Ameaças, seja implementada pelo processador REST. Ela permite que o usuário declare as
 * origens CORS que devem ser consideradas confiáveis.
 */
let optionsWindow = null;
/**
 * Interface com o Windows System Tray, destinada a permitir que o usuário interaja com o serviço Hekura executando em background, 
 * a saber:
 * (i) encerrar o aplicativo, removendo o serviço;
 * (ii) abrir a janela de Opções, permitindo, por exemplo, que o usuário adicione origens confiáveis.
 */
let tray = null;
/**
 * Sinal indicando que o eventual fechamento de alguma janela aberta não seja interpretado como o encerramento do
 * aplicativo e do serviço. 
 */
let isQuiting = false;
/**
 * Configuração do aplicativo
 */
let config = null;
/**
 * Child Process responsável pela execução do serviço em background
 */
let service = null;
/**
 * Mapa de mensagens enviadas ao processo de renderização de alertas e ainda aguardando resposta.
 * A chave do mapa é um UUID de identificação da mensagem e o valor, uma instância de RenderParams,
 * objeto capaz de resolver a Promise retornada ao processador Hekura de requisições REST
 */
 let params = new Map();

 /**
  * Valor do mapa de mensagens enviadas
  * @property { DelayedPromise } promise: promise retornada por askUser(), resolvida quando da recepção do evento user-answer
  * @property { UserQuestion } question: objeto contendo as informações necessárias à decisão do usuário
  */
class RenderParams {
	constructor(promise, question) {
		this.promise = promise;
		this.question = question;
	}
}
/**
 * Exibe janela de alerta ao usuário, informando que uma operação está sendo requerida por uma origem confiável,
 * para sua aprovação. Permite que a contramedida (iii) definida no documento Modelo de Ameaças seja implementada.
 * @param { WarnMessage } message: mensagem recebida do processo responsável pela execução do serviço Hekura
 * @returns Promise<boolean> a ser resolvida quando o evento user-answer for recebido
 */
function askUser(message) {
	return new Promise((resolve, reject) => {
		let idx = OPERATIONS.findIndex((value) => { return message.operationId === value; });
		if (idx < 0) return reject(new Error('Valor da propriedade operationId do objeto de mensagem não conhecido'));
		if (config.everBeenDisturbed(message.referer, message.operationId)) return resolve(true);

		let msg = sprintf('Você recebeu uma solicitação para %s do serviço web residente em %s. Deseja prosseguir?', ACTIONS[idx], message.referer);
		let question = new UserQuestion(message, msg);
		params.set(question.msgId, new RenderParams(new DelayedPromise(resolve, reject), question));
		let askWindow = new BrowserWindow({
			width: 800,
			height: 500,
			minWidth: 800,
			minHeight: 400,
			icon: ICO,
			minimizable: false,
			alwaysOnTop: true,
			skipTaskbar: true,
			title: APP_TITLE,
			webPreferences: {
				preload: path.join(__dirname, 'ask.js'),
				additionalArguments: [ "--id=" + question.msgId ]
			},
			show: false
		});
		askWindow.setMenu(null);
		askWindow.loadFile(path.join(__dirname, 'res', 'ask.html'));
		askWindow.once('ready-to-show', () => { askWindow.show(); });
	});
}

/**
 * Evento emitido pelo processo de renderização dos diálogos de alerta, durante o seu processo de carga,
 * para o preenchimento dos seus objetos HTML. Retorna as informações necessárias à decisão do usuário.
 * @param { IpcMainEvent } evt: evento recebido
 * @param { String } id: identificador da mensagem de alerta recebida
 * @returns a instância de UserQuestion com as informações necessárias
 */
ipcMain.on('get-params', (evt, id) => {
	let ret = null;
	let param = params.get(id);
	if (param) ret = param.question;
	evt.returnValue = ret;
});

/**
 * Evento emitido pelo processo de renderização dos diálogos de alerta, quando o usuário responde ao alerta. Resolve 
 * (ou rejeita) a promise emitida pela função askUser().
 * @param { IpcMainEvent } evt: evento recebido
 * @param { UserAnswer } answer: objeto que transporta as decisões do usuário
 */
ipcMain.on('user-answer', (evt, answer) => {
	let param = params.get(answer.msgId);
	if (param) {
		if (answer.dontAsk) config.addDoNotDisturb(param.question.referer, param.question.operationId);
		params.delete(answer.msgId);
		param.promise.resolve(answer.response);
		evt.returnValue = true;
	}
	else {
		tray.displayBalloon({
			iconType: 'error',
			title: APP_TITLE,
			content: 'Não foi possível processar a resposta fornecida pelo usuário por falha na comunicação interna do aplicativo.',
			noSound: false
		});
		evt.returnValue = false;
	}
});

/**
 * Evento emitido pelo processo de renderização dos diálogos de alerta, para relatar erro ocorrido.
 * @param { IpcMainEvent } evt: evento recebido
 * @param { String } message: mensagem de erro
 */
ipcMain.on('report-error', (evt, message) => {
	tray.displayBalloon({
		iconType: 'error',
		title: APP_TITLE,
		content: message,
		noSound: false
	});
	evt.returnValue = true;
});

/**
 * Exibe diálogo para tomada de decisão
 */
 ipcMain.on('ask-dialog', (evt, param) => {
	dialog.showMessageBox(optionsWindow, {
		message: param.message,
		type: 'question',
		buttons: [ 'Não', 'Sim' ],
		defaultId: 0,
		title : param.title,
		checkboxLabel: 'Não perguntar novamente'
	})
	.then((choice) => {
		evt.returnValue = choice;
	})
	.catch(() => {
		evt.returnValue = {
			response: 0,
			checkboxChecked: false
		}
	});
});

/**
 * Retorna a configuração de inicialização do aplicativo
 */
ipcMain.on('get-config', (evt) => { evt.returnValue = config; });

/**
 * Dialogo de mensagem
 *	options: see https://www.electronjs.org/docs/api/dialog#dialogshowmessageboxbrowserwindow-options
 */
 ipcMain.on('show-message', (evt, options) => { 
	dialog.showMessageBox(optionsWindow, options);
	evt.returnValue = true;
});

/**
 * Diálogo padrão de abertura de arquivo
 * 	options: see https://www.electronjs.org/docs/api/dialog#dialogshowopendialogsyncbrowserwindow-options
 */
 ipcMain.on('open-file', (evt, options) =>{ evt.returnValue = dialog.showOpenDialogSync(optionsWindow, options); });

/**
 * Atualiza a configuração corrente
 *	newCfg: instance of module.Config
 */
 ipcMain.on('update-config', (evt, newCfg) => {
	config = Object.setPrototypeOf(newCfg, Config.prototype); 
	evt.returnValue = true;
});

/**
 * Restarta a aplicação (por conta de mudanças nas suas configurações de inicialização)
 */
ipcMain.on('relaunch-app', (evt) => {
	app.relaunch();
	app.quit();
	evt.returnValue = true;
});


/**
 * Inicialização da aplicação, onde as seguintes tarefas são executadas:
 * (i) carga do arquivo de opções do aplicativo
 * (ii) lançamento do processo de execução do serviço Hekura
 * (iii) criação da janela de Opções do serviço (invisível)
 * (iv) inicialização do aplicativo junto Windows System Tray
 */
app.on('ready', () => {
	try { config = Config.load(OPTIONS); }
	catch (e) {
		console.error('Ocorreu o seguinte erro ao carregar o arquivo de configuração:');
		console.error(e.toString());
		console.error(JSON.stringify(e, null, 2));
		console.error('Assumindo o valor padrão...');
		config = new Config();
	}

	let logArg = '--log='.concat(JSON.stringify(config.logOptions));
	let svrArg = '--server='.concat(JSON.stringify(config.serverOptions));
	service = cp.fork(`${__dirname}/service.js`, [ logArg, svrArg ], { cwd: __dirname, detached: false });
	service.on('message', (message) => {
		if (message.signal === Message.WARN) {
			askUser(message).then((accept) => {
				let response = new WarnResponse(message.msgId, accept);
				service.send(response);
			}).catch((reason) => {
				tray.displayBalloon({
					iconType: 'error',
					title: APP_TITLE,
					content: sprintf('Ocorreu o seguinte erro ao solicitar a aprovação do usuário: %s', reason.toString()),
					noSound: false
				});
			});
		}
	});

	optionsWindow = new BrowserWindow({
		width: 800,
		height: 500,
		minWidth: 800,
		minHeight: 500,
		icon: ICO,
		webPreferences: {
			preload: path.join(__dirname, 'options.js')
		},
		show: false
	});
	optionsWindow.setMenu(Menu.buildFromTemplate(optionsMenu));
	optionsWindow.webContents.loadFile(IFACE);
	//optionsWindow.webContents.openDevTools();

	/**
	 * Evento de fechamento da janela. Evita que o apliciativo se encerre e
	 * torna invisível a janela
	 */
	optionsWindow.on('close', (evt) => {
		if (!isQuiting) {
			evt.preventDefault();
			optionsWindow.hide();
			evt.returnValue = false;
		}
	});
	/**
	 * Evento de minimização da janela. Ao invés de minimizada na barra de tarefas,
	 * a janela é tornada invisível.
	 */
	optionsWindow.on('minimize', (evt) => {
		evt.preventDefault();
		optionsWindow.hide();
	});

	tray = new Tray(ICO);
	tray.setContextMenu(Menu.buildFromTemplate(contextMenu));
	tray.setToolTip(APP_TITLE);
	/**
	 * Clique do mouse no ícone do System Tray.
	 * Exibe a lista de origens confiáveis sendo atendida pelo serviço
	 */
	tray.on('click', () => {
		let contents = 'Atendendo às seguintes origens confiáveis:';
		if (config.serverOptions.trustedOrigins.origins.length > 0) {
			config.serverOptions.trustedOrigins.origins.forEach((item) => {
				contents = contents.concat(' ').concat(item.origin);
			});
		}
		else contents = contents.concat(' nenhuma origem cadastrada');
		tray.displayBalloon({
			icon: ICO,
			iconType: 'custom',
			title: APP_TITLE,
			content: contents,
			noSound: true
		});
	});
});

/**
 * Finalização do aplicativo, realizando as seguintes tarefas:
 * (i) salvar as configurações correntes do apliciativo
 * (ii) enviar sinal de finalização ao processo que executa o serviço Hekura em background
 */
app.on('before-quit', () => {
	isQuiting = true;
	try { config.store(OPTIONS); }
	catch (e)
	{
		console.error('Ocorreu o seguinte erro ao salvar o arquivo de configuração:');
		console.error(e.toString());
		console.error('Todas as alterações eventualmente feitas serão perdidas.');
	}

	try { if (service) service.send(new Message(Message.STOP)); }
	catch (e) {
		console.error('Ocorreu o seguinte erro ao tentar parar o serviço Hekura:');
		console.error(e.toString());
	}
});