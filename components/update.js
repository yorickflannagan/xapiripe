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
		this.restart;
	}
	/**
	 * Define o indicador de reinício do aplicativo
	 * @param { Boolean } yes indicador de reinício do aplicativo 
	 * @returns a instância corrente
	 */
	restart(yes) {
		this.restart = yes;
		return this;
	}
}

/**
 * Lida com os eventos Squirrel de atualização da aplicação
 */
class UpdateManager {
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
		this.debug = (typeof env.DEBUG !== 'undefined');		// env.DEBUG indica que esta classe está sendo depurada (com ou sem Squirrel)
		this.development = argv[0].endsWith('electron.exe');	// Indicador de não utilização do Squirrel
		this.updateArgument;									// Comando Squirrel
		this.updateEvent = false;								// Indicador de execução sob controle do Squirrel
		this.regAddArguments;									// Argumentos para execução do comando REG ADD
		this.regDeleteArguments;								// Argumentos para execução do comando REG DELETE
		this.appDir =  path.resolve(env.USERPROFILE, '.' + distribution.productName.toLowerCase());	// Diretório dos dados da aplicação
		this.updateURL = distribution.updateURL;				// URL de atualização
		this.updateInterval = this.debug? 1000 * 60 * 1 : 1000 * 60 * 15;	// Timeout de execução da verificação de atualização
		this.callback = callback;								// Função de controle da atualização
		let offset = this.development && this.debug ? 1 : 0;	// Se offset = 1 os comandos Squirrel devem ser adicionados à mão
		if (this.development && !this.debug) return;			// Se o Squirrel não é utilizado e a classe não está sendo depurada, nada é feito

		switch(argv.length) {
		case 3 + offset:
			let registryData = path.resolve(nodeProcess.env.LOCALAPPDATA, distribution.productName, 'app-' + argv[2 + offset], distribution.exe);
			this.regAddArguments = [ 'ADD', REG_KEY, '/v', distribution.productName, '/t', 'REG_SZ', '/d', registryData, '/f' ];
		case 2 + offset:
			this.updateArgument = argv[1 + offset];
			this.updateEvent = true;
			this.regDeleteArguments = [ 'DELETE', REG_KEY, '/v', distribution.productName, '/f' ];
			break;
		default: return;
		}
		// Se classe em depuração sem utilização do Squirrel, exibe o resultado da inicialização
		if (this.debug && this.development) console.log(sprintf(DEBUG_INIT_MSG, this.updateArgument, this.regAddArguments, this.regDeleteArguments, this.appDir, this.updateURL));
	}
	#createAppDir(appDir) {
		try {
			if (!fs.existsSync(appDir)) fs.mkdirSync(appDir);
			return new HandleEvtResult(true);
		}
		catch (e) { return new HandleEvtResult(false, e.toString()); }
	}
	#updateRegistry(args) {
		let ret = cp.spawnSync('REG', args, { encoding: 'utf-8', shell: true });
		if (ret.signal) return new HandleEvtResult(false, ret.signal);
		if (ret.status != 0) return new HandleEvtResult(false, ret.stderr);
		return new HandleEvtResult(true);
	}
	/**
	 * Lida com os eventos de atualização, controlados pelo Squirrel
	 * @returns uma instância de HandleEvtResult, com o resultado do processamento dos eventos
	 */
	handleUpdateEvents() {
		if ((this.development && !this.debug) || !this.updateEvent) return new HandleEvtResult(true).restart(false);
		let ret;
		switch(this.updateArgument) {
		case '--squirrel-install':
			ret = this.#createAppDir(this.appDir);
			if (ret.success) ret = this.#updateRegistry(this.regAddArguments);
			return ret.restart(true);
		case '--squirrel-updated':
		case '--squirrel-obsolete':
			ret = this.#updateRegistry(this.regAddArguments);
			return ret.restart(true);
		case '--squirrel-uninstall':
			ret = this.#updateRegistry(this.regDeleteArguments);
			return ret.restart(true);
		default: return new HandleEvtResult(true).restart(false);
		}
	}
	/**
	 * Inicia a tarefa periódica de verificar se existem atualizações do produto.
	 * Em produção, verifica a cada 15 minutos; se a variável de ambiente DEBUG estiver
	 * definida, este intervalo é de 1 minuto.
	 */
	startAutoUpdater() {
		if (this.development && !this.debug) return;	// Permite "depurar" a atualização, reduzindo o intervalo de buca
		autoUpdater.setFeedURL(this.updateURL);
		autoUpdater.on('error', (error) => {
			this.callback(UpdateManager.ERROR_MESSAGE, sprintf(UPDATE_ERROR, error.toString()));
		});
		autoUpdater.on('update-downloaded', (evt, releaseNotes, releaseName) => {
			if (this.callback(UpdateManager.UPDATE_MESSAGE, sprintf(RESTART_MSG, releaseName))) autoUpdater.quitAndInstall();
		});
		setInterval(() => { autoUpdater.checkForUpdates(); }, this.updateInterval);
	}
}

module.exports = { UpdateManager };