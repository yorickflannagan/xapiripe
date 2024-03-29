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
 * @version 1.1.1
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
const { Config } = require('./config');
const { sprintf } = require('../components/wanhamou');
const { Message, WarnResponse, UserQuestion, LogMessage, InfoMessage } = require('./module');
const { Distribution, DelayedPromise } = require('../components/options');
const { UpdateManager } = require('../components/update');
const { Lock } = require('../components/lock');
const fs = require('fs');


const DISTRIBUTION_FILE = path.resolve(__dirname, 'distribution.json');
const ICON_FILE = path.resolve(__dirname, 'res', 'signature-32x32.ico');
const OPTIONS_HTML = path.resolve(__dirname, 'res', 'options.html');
const ASK_HTML = path.resolve(__dirname, 'res', 'ask.html');
const ASK_JS = path.resolve(__dirname, 'ask.js');
const LICENCE = 'https://opensource.org/licenses/LGPL-3.0';
const HELP_URL = 'file:///' + path.resolve(__dirname, 'res', 'help.html');

const APP_UPDATE = 'Atualização do aplicativo';
const APP_EXIT = 'Finalização do aplicativo';
const APP_FAILURE = 'Falha no Serviço criptográfico';
const UNKNOWN_PROPERTY = 'Valor da propriedade operationId do objeto de mensagem não conhecido';
const ASK_MESSAGE = 'Atenção! O aplicativo no endereço %s enviou %s. Você concorda em realizar essa operação?';
const ASK_FAILURE = 'Ocorreu o seguinte erro ao solicitar a aprovação do usuário: %s';
const CHECK_LOG = 'Erro em processo interno. Consulte o log do aplicativo';
const IPC_FAILURE = 'Erro desconhecido na comunicação interna do aplicativo';
const DONT_ASK = 'Não perguntar novamente';
const DISTRIBUTION_FAILURE = 'Ocorreu o seguinte erro ao carregar o arquivo de identificação da distribuição: %s. A aplicação não está funcionando apropriadamente e será fechada.';
const CONFIG_FAILURE = 'Ocorreu o seguinte erro ao processar o arquivo de configuração: %s. Assumindo os valores padrão.';
const ORIGINS_INFO = 'Atendendo às seguintes origens confiáveis:';
const ORIGINS_NO_INFO = ' nenhuma origem cadastrada';
const QUIT_FAILURE = 'Ocorreu o seguinte erro ao salvar o arquivo de configuração: %s. Todas as alterações eventualmente feitas serão perdidas.';
const CHOICE_BUTTONS = [ 'Sim', 'Não' ];


/**
 * Informações sobre a distribuição do produto
 */
let distribution = null;
/**
 * Slot para guarda de erros ocorridos durante o processamento Squirrel.
 */
let lastEventError = null;
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
 * Localização do arquivo de opções (dependente da distribuição)
 */
let optionsFile = null;

/**
 * Selo indicativo de instância inicializada. Arquivo para acesso exclusivo é criado no diretório da aplicação
 */
let locker = null;


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
const OPERATIONS = [ 'enumerateDevices', 'generateCSR', 'installCertificates', 'enumerateCertificates', 'sign', 'verify' ];
const ACTIONS = [
	'solicitação para enumerar dispositivos criptográficos presentes',
	'solicitação para assinar requisição de certificado digital',
	'solicitação para instalar certificado assinado',
	'solicitação para enumerar certificados de assinatura instalados',
	'o documento a seguir para ser assinado',
	'o documento a seguir para ser verificado'
];
function askUser(message) {
	return new Promise((resolve, reject) => {
		let idx = OPERATIONS.findIndex((value) => { return message.operationId === value; });
		if (idx < 0) return reject(new Error(UNKNOWN_PROPERTY));
		if (config.everBeenDisturbed(message.referer, message.operationId)) return resolve(true);

		let msg = sprintf(ASK_MESSAGE, message.referer, ACTIONS[idx]);
		let question = new UserQuestion(message, msg);
		params.set(question.msgId, new RenderParams(new DelayedPromise(resolve, reject), question));
		let width = message.value ? 800 : 600;
		let height = message.value ? 500 : 250;
		let askWindow = new BrowserWindow({
			width: width,
			height: height,
			minWidth: width,
			minHeight: height,
			icon: ICON_FILE,
			minimizable: false,
			alwaysOnTop: true,
			skipTaskbar: true,
			title: distribution.productName,
			webPreferences: {
				preload: ASK_JS,
				additionalArguments: [ "--id=" + question.msgId ]
			},
			show: false
		});
		askWindow.setMenu(null);
		askWindow.loadFile(ASK_HTML);
		askWindow.once('ready-to-show', () => { askWindow.show(); });
	});
}

/**
 * Função chamada pelo dispositivo de atualização, para feedback ao usuário
 * @param { Number } type: tipo de mensagem a ser exibida
 * @param { String } msg: mensagem a ser exibida
 * @returns um indicador para a escolha do usuário, se necessária
 */
function updateCallback(type, msg) {
	switch(type) {
	case UpdateManager.ERROR_MESSAGE:
		if (msg.length > 64) service.send(new LogMessage(msg));
		tray.displayBalloon({
			iconType: 'error',
			title: APP_UPDATE,
			content: msg.length > 64 ? CHECK_LOG : msg,
			noSound: false
		});
		return true;
	case UpdateManager.UPDATE_MESSAGE:
		let choice = dialog.showMessageBoxSync({
			message: msg,
			type: 'question',
			buttons: CHOICE_BUTTONS,
			defaultId: 0,
			title: APP_UPDATE
		});
		return choice == 0;
	case UpdateManager.INFO_MESSAGE:
		service.send(new InfoMessage(msg));
	}
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
			title: distribution.productName,
			content: IPC_FAILURE,
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
	if (message.length > 64) service.send(new LogMessage(message));
	tray.displayBalloon({
		iconType: 'error',
		title: distribution.productName,
		content: message.length > 64 ? CHECK_LOG : message,
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
		buttons: CHOICE_BUTTONS,
		defaultId: 0,
		title : param.title,
		checkboxLabel: DONT_ASK
	})
	.then((choice) => {
		evt.returnValue = choice;
	})
	.catch(() => {
		evt.returnValue = {
			response: 0,
			checkboxChecked: false
		};
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
 * (i)		criação do arquivo de lock exclusivo da aplicação
 * (ii)		carga do arquivo de distribuição da aplicação
 * (iii)	processamento dos eventos de atualização
 * (iv)		carga do arquivo de opções do aplicativo
 * (v)		lançamento do processo de execução do serviço Hekura
 * (vi)		criação da janela de Opções do serviço (invisível)
 * (vii)	inicialização do aplicativo junto Windows System Tray
 * (viii)	inicialização da atualizaçao
 */
app.on('ready', () => {
	try {
		locker = new Lock(__dirname);
		locker.createLock();
	}
	catch (e) {
		locker = null;
		app.quit();
		return;
	}

	try { distribution = Distribution.load(DISTRIBUTION_FILE); }
	catch (e) {
		setInterval(() => { app.quit(); }, 5000);
		dialog.showMessageBoxSync({
			title: APP_FAILURE,
			type: 'error',
			message: sprintf(DISTRIBUTION_FAILURE, e.toString())
		});
		return;
	}

	let manager = new UpdateManager(process, distribution, updateCallback);
	let ret = manager.handleUpdateEvents();
	if (!ret.success) {
		if (ret.mustRestart) {
			if (!lastEventError) lastEventError = ret.stderror;
		}
		else {
			dialog.showMessageBoxSync({
				message: ret.stderror,
				type: 'error',
				title: APP_UPDATE
			});
		}
	}
	if (ret.mustRestart) {
		app.quit();
		return;
	}

	optionsFile = path.resolve(manager.appDir, 'options.json');
	let launchError = null;
	config = new Config(distribution.productName);
	try { if (fs.existsSync(optionsFile)) config = Config.load(optionsFile); }
	catch (e) { launchError = sprintf(CONFIG_FAILURE, e.toString()); }
	if (!config.logOptions.path) config.logOptions.path = manager.appDir;

	let logArg = '--log='.concat(JSON.stringify(config.logOptions));
	let svrArg = '--server='.concat(JSON.stringify(config.serverOptions));
	let restArg = '--service='.concat(distribution.productName);
	service = cp.fork(`${__dirname}/service.js`, [ logArg, svrArg,restArg ], { cwd: __dirname, detached: false });
	service.on('message', (message) => {
		switch(message.signal) {
		case Message.WARN:
			askUser(message).then((accept) => {
				let response = new WarnResponse(message.msgId, accept);
				service.send(response);
			}).catch((reason) => {
				let msg = sprintf(ASK_FAILURE, reason.toString());
				if (msg.length > 64) service.send(new LogMessage(msg));
				tray.displayBalloon({
					iconType: 'error',
					title: distribution.productName,
					content: msg.length > 64 ? CHECK_LOG : msg,
					noSound: false
				});
			});
			break;
		case Message.ERROR:
			dialog.showMessageBoxSync({
				title: distribution.productName,
				type: 'error',
				message: message.error
			});
			service = null;
			app.quit();
			break;
		default:
		}
	});

	optionsWindow = new BrowserWindow({
		width: 800,
		height: 500,
		minWidth: 800,
		minHeight: 500,
		icon: ICON_FILE,
		webPreferences: {
			preload: path.join(__dirname, 'options.js')
		},
		show: false
	});
	optionsWindow.setMenu(Menu.buildFromTemplate([{ label: 'Fechar', click: () => { optionsWindow.close(); }}]));
	optionsWindow.webContents.loadFile(OPTIONS_HTML);
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

	tray = new Tray(ICON_FILE);
	tray.setContextMenu(Menu.buildFromTemplate([
		{ label: 'Opções do serviço...', click: () => { optionsWindow.show(); }},
		{ 'type': 'separator' },
		{ label: 'Ajuda', click: () => { shell.openExternal(HELP_URL); }},
		{ label: 'Licença', click: () => { shell.openExternal(LICENCE); }},
		{ label: 'Sobre...', click: () => {
			let contents = distribution.productName
				.concat(' ').concat(app.getVersion())
				.concat(', ').concat(distribution.productDescription)
				.concat(',').concat(distribution.company)
				.concat('. Distribuído por: ').concat(distribution.distributorId);
			tray.displayBalloon({
				iconType: 'info',
				title: 'Sobre o ' + distribution.productName,
				content: contents,
				noSound: true
			});
		}},
		{ 'type': 'separator' },
		{ label: 'Sair', click: () => { app.quit(); }}
	]));
	tray.setToolTip(distribution.productName);

	if (lastEventError) {
		if (lastEventError.length > 64) service.send(new LogMessage(lastEventError));
		tray.displayBalloon({
			iconType: 'error',
			title: APP_UPDATE,
			content: lastEventError.length > 64 ? CHECK_LOG : lastEventError,
			noSound: false
		});
		lastEventError = null;
	}
	if (launchError) {
		if (launchError.length > 64) service.send(new LogMessage(launchError));
		tray.displayBalloon({
			iconType: 'error',
			title: 'Lançamento do aplicativo',
			content: launchError.length > 64 ? CHECK_LOG : launchError,
			noSound: false
		});
	}
	launchError = null;
	manager.startAutoUpdater();

	/**
	 * Clique do mouse no ícone do System Tray.
	 * Exibe a lista de origens confiáveis sendo atendida pelo serviço
	 */
	tray.on('click', () => {
		let contents = ORIGINS_INFO;
		if (config.serverOptions.trustedOrigins.origins.length > 0) {
			config.serverOptions.trustedOrigins.origins.forEach((item) => {
				contents = contents.concat(' ').concat(item.origin);
			});
		}
		else contents = contents.concat(ORIGINS_NO_INFO);
		tray.displayBalloon({
			icon: ICON_FILE,
			iconType: 'custom',
			title: distribution.productName,
			content: contents,
			noSound: true
		});
	});
});

/**
 * Finalização do aplicativo, realizando as seguintes tarefas:
 * (i)		salvar as configurações correntes do apliciativo
 * (ii)		enviar sinal de finalização ao processo que executa o serviço Hekura em background
 * (iii)	liberar o arquivo de lock exclusivo da aplicação
 */
app.on('before-quit', () => {
	isQuiting = true;
	try { if(config) config.store(optionsFile); }
	catch (e)
	{
		dialog.showMessageBoxSync({
			title: APP_EXIT,
			type: 'error',
			message: sprintf(QUIT_FAILURE, e.toString())
		});
	}

	try { if (service) service.send(new Message(Message.STOP)); }
	catch (e) {}

	if (locker) locker.releaseLock();
});