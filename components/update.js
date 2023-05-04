/**
 * @file Handler de atualização dos aplicativos.
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const { autoUpdater } = require('electron');
const { sprintf } = require('./wanhamou');
const { Config } = require('../appservice/config');

const REG_KEY = 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run';
const UPDATE_ERROR = 'Ocorreu o seguinte erro na atualização do aplicativo: %s. O serviço não está funcionando apropriadamente.';
const RESTART_MSG = 'A nova versão %s do serviço foi baixada e estará disponível quando o aplicativo reiniciar. Deseja fazer isso agora?';
const DEBUG_INIT_MSG = 'Depuração dos eventos Squirrel iniciada com os seguintes argumentos:\n\tupdateArgument: %s\n\tregAddArguments: %s\n\tregDeleteArguments: %s\n\tappDir: %s\n\tupdateURL: %s\n\t';

/**
 * Resultado do processamento de um evento Squirrel
 * @property { Boolean } success: indicador de sucesso da operação
 * @property { String } stderror: mensagem de erro retornado pelo processo chamado, se success for false
 * @property { boolean } restart: indicador de que a aplicação precisa ser reiniciada por demanda do Squirrel, independente do resultado da operação
 */
class HandleEvtResult {
	/**
	 * Cria uma nova instância do objeto
	 * @param { Boolean } success indicador de sucesso da operação. Obrigatório
	 * @param { String } stderror mensagem de erro. Optional
	 */
	constructor(success, stderror) {
		this.success = success;
		this.stderror = stderror;
		this.mustRestart = false;
	}
	/**
	 * Define o indicador de reinício do aplicativo
	 * @param { Boolean } yes indicador de reinício do aplicativo 
	 * @returns a instância corrente
	 */
	restart(yes) {
		this.mustRestart = yes;
		return this;
	}
}

/**
 * Lida com os eventos Squirrel de atualização da aplicação
 */
class UpdateManager {
	/* jshint ignore:start */
	/**
	 * Mensagem de erro durante a atualização
	 * @member { Number }
	 * @default 1
	 */
	static ERROR_MESSAGE = 1;
	/**
	 * Mensagem indicativa de que o restart é necessário
	 * @member { Number }
	 * @default 2
	 */
	static UPDATE_MESSAGE = 2;
	/**
	 * Sinal para logging da atualização
	 */
	static INFO_MESSAGE = 3;
	/* jshint ignore:end */
	/**
	 * Cria uma nova instância do gerenciador de atualização
	 * @param { Process } nodeProcess instância do objeto global process
	 * @param { Distribution } distribution identificação da distribuição do produto
	 * @param { Function } callback função a ser chamada quando houver necessidade de comunicação com o processo principal da aplicação,
	 * durante o processo contínuo de verificação de atualização.
	 * Deve ter a assinatura (type, message), a saber:
	 * - type: tipo de mensagem (ver propriedades estáticas da classe);
	 * - message: mensagem a ser exibida ao usuário. Opcional;
	 * - retorna um indicador de que a ação requerida pode prosseguir.
	 */
	constructor(nodeProcess, distribution, callback) {
		let argv = nodeProcess.argv;
		let env = nodeProcess.env;
		this.debug = (typeof env.DEBUG !== 'undefined') || false;		// env.DEBUG indica que esta classe está sendo depurada (com ou sem Squirrel)
		this.development = (argv[0].endsWith('electron.exe')) || false;	// Indicador de não utilização do Squirrel
		this.updateArgument = '';										// Comando Squirrel
		this.updateEvent = false;										// Indicador de execução sob controle do Squirrel
		this.regAddArguments = null;									// Argumentos para execução do comando REG ADD
		this.regDeleteArguments = null;									// Argumentos para execução do comando REG DELETE
		this.appDir =  path.resolve(env.USERPROFILE, '.' + distribution.productName.toLowerCase());	// Diretório dos dados da aplicação
		this.updateURL = distribution.updateURL;						// URL de atualização
		this.updateInterval = distribution.interval * 1000;				// Timeout de execução da verificação de atualização
		this.callback = callback;										// Função de controle da atualização
		this.trustedEntries = distribution.trusted;						// 
		let offset = this.development && this.debug ? 1 : 0;			// Se offset = 1 os comandos Squirrel devem ser adicionados à mão
		if (this.development && !this.debug) return;					// Se o Squirrel não é utilizado e a classe não está sendo depurada, nada é feito

		switch(argv.length) {
		case 3 + offset:
			let registryData = path.resolve(nodeProcess.env.LOCALAPPDATA, distribution.productName, 'app-' + argv[2 + offset], distribution.productName.toLowerCase() + '.exe');
			this.regAddArguments = [ 'ADD', REG_KEY, '/v', distribution.productName, '/t', 'REG_SZ', '/d', registryData, '/f' ];
			/* falls through */
		case 2 + offset:
			this.updateArgument = argv[1 + offset];
			this.updateEvent = true;
			this.regDeleteArguments = [ 'DELETE', REG_KEY, '/v', distribution.productName, '/f' ];
		}
		// Se classe em depuração sem utilização do Squirrel, exibe o resultado da inicialização
		if (this.debug && this.development) console.log(sprintf(DEBUG_INIT_MSG, this.updateArgument, this.regAddArguments, this.regDeleteArguments, this.appDir, this.updateURL));
	}
	createAppDir(appDir, evt) {
		if (evt.success) {
			try { if (!fs.existsSync(appDir)) fs.mkdirSync(appDir); }
			catch (e) { evt.success = false; evt.stderror = e.toString(); }
		}
		return evt;
	}
	execCommand(cmd, args, evt) {
		if (evt.success) {
			let ret = cp.spawnSync(cmd, args, { encoding: 'utf-8', shell: true });
			if (ret.signal) { evt.success = false; evt.stderror = ret.signal; }
			else if (ret.status != 0) { evt.success = false; evt.stderror = ret.stderr; }
		}
		return evt;
	}
	updateRegistry(args, evt) {
		return this.execCommand('REG', args, evt);
	}
	shortcutIcon(cmd, evt) {
		if (evt.success) {
			let appExec = process.execPath;
			let appFolder = path.dirname(appExec);
			let updater = path.join(path.dirname(appFolder), 'Update.exe');
			let ret = cp.spawnSync(updater, [ cmd, appExec ], { encoding: 'utf-8', shell: true });
			if (ret.signal) { evt.success = false; evt.stderror = ret.signal; }
			else if (ret.status != 0) { evt.success = false; evt.stderror = ret.stderr; }
		}
		return evt;
	}
	initializeOptionsFile(dir, entries, evt) {
		if (evt.success) {
			let options = path.join(dir, 'options.json');
			let config = Config.load(options);
			entries.forEach((item) => {
				let idx = config.serverOptions.trustedOrigins.origins.findIndex((elem) => {
					return (elem.origin === item);
				});
				if (idx === -1) config.setOrigin(item);
			});
			try { config.store(options); }
			catch (e) {}
		}
		return evt;
	}
	/**
	 * Lida com os eventos de atualização, controlados pelo Squirrel
	 * @returns uma instância de HandleEvtResult, com o resultado do processamento dos eventos
	 */
	handleUpdateEvents() {
		if ((this.development && !this.debug) || !this.updateEvent) return new HandleEvtResult(true).restart(false);

		let ret = new HandleEvtResult(true);
		switch(this.updateArgument) {
		case '--squirrel-install':
			ret = this.createAppDir(this.appDir, ret);
			/* falls through */
		case '--squirrel-updated':
			ret = this.updateRegistry(this.regAddArguments, ret);
			if (!this.debug) ret = this.shortcutIcon('--createShortcut', ret);
			ret = this.initializeOptionsFile(this.appDir, this.trustedEntries, ret);
			/* falls through */
		case '--squirrel-obsolete':
			return ret.restart(true);
		case '--squirrel-uninstall':
			ret = this.updateRegistry(this.regDeleteArguments, ret);
			if (!this.debug) ret = this.shortcutIcon('--removeShortcut', ret);
			return ret.restart(true);
		default: return ret.restart(false);
		}
	}
	/**
	 * Inicia a tarefa periódica de verificar se existem atualizações do produto.
	 */
	startAutoUpdater() {
		if (this.development && !this.debug) return;	// Permite "depurar" a atualização, reduzindo o intervalo de busca
		autoUpdater.setFeedURL(this.updateURL);
		autoUpdater.on('error', (error) => {
			let msg = sprintf(UPDATE_ERROR, error.toString());
			this.callback(UpdateManager.ERROR_MESSAGE, msg);
		});
		autoUpdater.on('update-available', () => {
			this.callback(UpdateManager.INFO_MESSAGE, 'Nova versão disponível para download');
		});
		autoUpdater.on('update-downloaded', (evt, releaseNotes, releaseName) => {
			let msg = sprintf(RESTART_MSG, releaseName);
			if (this.callback(UpdateManager.UPDATE_MESSAGE, msg)) autoUpdater.quitAndInstall();
		});
		setInterval(() => { autoUpdater.checkForUpdates(); }, this.updateInterval);
	}
}

module.exports = { UpdateManager };