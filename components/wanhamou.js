/**
 * @file Dispositivo de log simples
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const path = require('path');
const fs = require('fs');


/**
 * Dispositivo simplificado de log
 * @namespace Wanhamou
 */

/**
 * Opções de inicialização do log
 * @class LogOptions
 * @memberof Wanhamou
 * @property { String } path	Diretório de localização do arquivo de log. Valor default __dirname
 * @property { String } fname	Padrão de nome do log, na forma [nome]-n.[ext], onde nome é o nome e ext a extensão 
 * que se deseja para o arquivo. Valor default xapiripe-n.log
 * @property { Number } maxSize	Tamanho máximo (em KB) do arquivo de log antes de ser obrigado a rotacionar. Valor default: 2048
 * @property { Number } rotate	Quantidade máxima de arquivos de log antes que seja necessário sobrescrever o mais antigo. Valor default: 5
 * @property { Number } level	Nível corrente do log. Serão logados somente as mensagens com valor igual ou maior. Valor default INFO
 */


/**
 * Níveis de log
 */
class LogLevel {
	/* jshint ignore:start */
	/**
	 * Indicador de mensagem de depuração
	 * @member { Number }
	 * @default 0
	 */
	 static DEBUG = 0;

	 /**
	  * Indicador de mensagem informativa
	  * @member { Number }
	  * @default 1
	  */
	 static INFO = 1;
 
	 /**
	  * Indicador de mensagem de alerta
	  * @member { Number }
	  * @default 2
	  */
	 static WARN = 2;
 
	 /**
	  * Indicador de mensagem de erro
	  * @member { Number }
	  * @default 3
	  */
	 static ERROR = 3;
	 /* jshint ignore:end */
}


/**
 * Dispositivo simplificado de log
 */
class LogDevice {
	/* jshint ignore:start */
	static cfgFilePath = __dirname;
	static cfgLogPattern = 'xapiripe-n.log';
	static cfgLogMaxSize = 2048;
	static cfgLogRotate = 5;
	static cfgLogLevel = LogLevel.INFO;

	static globalFD = 0;
	static refCount = 0;
	/* jshint ignore:end */

	/**
	 * Fornece uma nova configuração para o log
	 * @param { Object } options Objeto de configuração do log conforme {@link Wanhamou.LogOptions}
	 */
	static logConfig(options) {
		if (typeof options.path === 'string' && fs.existsSync(options.path)) this.cfgFilePath = options.path;
		if (typeof options.fname === 'string' && options.fname.includes('-n')) this.cfgLogPattern = options.fname;
		if (typeof options.maxSize === 'number') this.cfgLogMaxSize = options.maxSize;
		if (typeof options.rotate === 'number') this.cfgLogRotate = options.rotate;
		if (typeof options.level === 'number' && options.level >= LogLevel.DEBUG && options.level <= LogLevel.ERROR) this.cfgLogLevel = options.level;
	}

	/**
	 * Gets an instance of LogDevice to specified origin. Atenção: use sempre este método estático; não construa
	 * diretamente o objeto de log.
	 * @param { String } origin Log origin
	 * @returns an instance of LogDevice
	 */
	static getLogger(origin) {
		let ret = new LogDevice(origin);
		if (this.globalFD == 0) {
			try { this.globalFD = ret.openLogFile(); }
			catch (err) {
				console.error('Impossível abrir o arquivo de log: ' + err);
				console.error('Todos os registros de log subsequentes serão feitos na console');
			}
		}
		this.refCount++;
		return ret;
	}

	/**
	 * Fecha o arquivo de log, se não mais necessário
	 */
	 static releaseLogger() {
		 this.refCount--;
		 if (this.refCount == 0) {
			try {
				fs.closeSync(this.globalFD);
				this.globalFD = 0;
			}
			catch (err) { console.log('Erro ao fechar o arquivo de log: ' + err); }
		 }
	}

	constructor(origin) {
		this.origin = (typeof origin !== 'undefined') ? origin : 'Xapiripe';
	}
	openLogFile() {
		let i = 0;
		let fd = 0;
		let mtime = new Date();
		let oldest = '';
		while (i < LogDevice.cfgLogRotate && fd == 0) {
			let fName = path.join(LogDevice.cfgFilePath, LogDevice.cfgLogPattern.replace('-n', '-'.concat(i.toString())));
			if (fs.existsSync(fName)) {
				let stats = fs.lstatSync(fName);
				if (stats.size < LogDevice.cfgLogMaxSize * 1024) fd = fs.openSync(fName, 'a');
				else {
					if (stats.mtime.getTime() < mtime.getTime()) {
						oldest = fName;
						mtime = stats.mtime;
					}
				}
			}
			else fd = fs.openSync(fName, 'w');
			i++;
		}
		if (fd == 0) fd = fs.openSync(oldest, 'w');
		return fd;
	}
	rotate() {
		try {
			let stats = fs.fstatSync(LogDevice.globalFD);
			if (stats.size > LogDevice.cfgLogMaxSize * 1024) {
				try {
					fs.closeSync(LogDevice.globalFD);
					LogDevice.globalFD = this.openLogFile();
				}
				catch (e) {
					LogDevice.globalFD = 0;
					throw e;
				}
			}
		}
		catch (err) {
			console.error('Impossível rotacionar o arquivo de log: ' + err);
			console.error('Todos os registros de log subsequentes serão feitos na console');
		}
	}
	getLevelInfo(level) {
		switch (level) {
		case LogLevel.DEBUG: return 'DEBUG: ';
		case LogLevel.INFO: return 'INFO: ';
		case LogLevel.WARN: return 'WARN: ';
		}
		return 'ERROR: ';
	}

	/**
	 * Registra a mensagem fornecida, caso o nível corrente de log seja maior ou igual ao indicado. O registro de log tem o formato:
	 * [origem] SPC - SPC [UTCInstant] SPC - SPC [level] SPC: SPC [msg], onde<br>
	 * <ol>
	 * <li>origem é o nome fornecido como origem do log;</li>
	 * <li>UTCInstant é o instante corrente do registro em tempo zulu, como em: Tue, 25 Jan 2022 14:01:41 GMT;</li>
	 * <li>level é o nível do registro, a saber: DEBUG, INFO, WARN ou ERROR;</li>
	 * <li>msg é a mensagem informativa fornecida.</li>
	 * </ol>
	 * @param { Number } level	Indicador do nível da mensagem
	 * @param {String } msg		Mensagem de log
	 */
	log(level, msg) {
		if (level >= LogDevice.cfgLogLevel) {
			this.rotate();
			let cur = new Date();
			let logged = this.origin.concat(' - ', cur.toUTCString(), ' - ', this.getLevelInfo(level), msg, '\r\n');
			try { fs.writeSync(LogDevice.globalFD, logged); }
			catch(e) {
				switch (level) {
				case LogLevel.DEBUG: console.debug(logged); break;
				case LogLevel.INFO:  console.info(logged); break;
				case LogLevel.WARN:  console.warn(logged); break;
				case LogLevel.ERROR: console.error(logged);
				}
			}
		}
	}

	/**
	 * Registra a mensagem em nível de depuração
	 * @param { String } msg	Mensagem de log
	 */
	debug(msg) { this.log(LogLevel.DEBUG, msg); }

	/**
	 * Registra a mensagem em nível informativo
	 * @param { String } msg	Mensagem de log
	 */
	info(msg) { this.log(LogLevel.INFO, msg); }

	/**
	 * Registra a mensagem em nível de alerta
	 * @param { String } msg	Mensagem de log
	 */
	warn(msg) { this.log(LogLevel.WARN, msg); }
	
	/**
	 * Registra a mensagem em nível de erro
	 * @param { String } msg	Mensagem de log
	 */
	error(msg) { this.log(LogLevel.ERROR, msg); }
}

function beautify(input) {
	let output;
	try {
		let data = JSON.parse(input);
		output = JSON.stringify(data, null, 2);
	}
	catch (e)  { output = input; }
	return output;
}

function sprintf() {
	let output = '';
	if (arguments.length > 0) {
		let replacer = [];
		for (let i = arguments.length - 1; i > 0; i--) replacer.push(arguments[i]);
		let input = arguments[0];
		output = input.replaceAll('%s', () => { return replacer.pop(); });
	}
	return output;
}

module.exports = {
	LogLevel: LogLevel,
	Logger: LogDevice,
	beautify: beautify,
	sprintf: sprintf
};
