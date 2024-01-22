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
 * service.js - Background Hekura service
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
/* jshint -W053 */
'use strict';

const alert = require('alert');



(async function () {

	const path = require('path');
	const { Config } = require('./config');
	const { Message, WarnMessage } = require('./module');
	const { Logger, LogLevel, sprintf } = require('../components/wanhamou');
	const { CORSBlockade, HTTPServer, ServiceError } = require('../components/hekura');
	const { DelayedPromise } = require('../components/options');

	/**
	 * Instância de Hekura.HttpServer
	 */
	let service = null;

	/**
	 * Mapa de mensagens enviadas ao processo principal e ainda aguardando resposta.
	 * A chave do mapa é um UUID de identificação da mensagem e o valor, uma instância de DelayedPromise,
	 * objeto capaz de resolver a Promise retornada ao processador Hekura de requisições REST
	 */
	let messages = new Map();
 
	/**
	 * Dispositivo de log
	 */
	let logger = null;

	try {

		/**
		 * Libera recursos alocados, finaliza o serviço e encerra o processo.
		 */
		let quitService = async function() {
			if (service) await service.stop();
			process.exit();
		};

		/**
		 * Callback evocada sempre que o processador REST precisa alertar o usuário de que uma operação criptográfica
		 * foi requisitada, conforme contramedida (iii) do documento Modelo de Ameaças. A callback simplesmente
		 * envia uma mensagem ao processo principal da aplicação, responsável pela interação com o usuário, retornando
		 * uma Promise que só será resolvida quando a mensagem for respondida e captada pelo evento message disparado
		 * pelo processo corrente.
		 * @param { String } operationId: identificador da operação REST
		 * @param { String } referer: origem da requisição, conforme cabeçalho HTTP
		 * @param { String } value: conteúdo da requisição, no caso da operação sign
		 * @returns { Promise<boolean> } um indicador de aceitação da rerquisição, emitido pelo usuário.
		 */
		let approvalCallback = function(operationId, referer, value) {
			return new Promise((resolve, reject) => {
				let msg = new WarnMessage(operationId, referer, value);
				messages.set(msg.msgId, new DelayedPromise(resolve, reject));
				process.send(msg);
			});
		};

		let usage = function(code) {
			console.log([
				'uso: node service.js [--config=[path] | --log=[logJSON] --server=[serverJSON]]',
				'onde',
				'  path: caminho completo para o arquivo de configuração do aplicativo Signthing;',
				'  logJSON: string JSON com o mesmo conteúdo da seção logOptions do arquivo de configuração do Signthing e',
				'  serverJSON: string JSON com o mesmo conteúdo da seção serverOptions do arquivo de configuração do Signthing.',
				'',
				'Se o argumento --config estiver presente, todos os demais são ignorados;',
				'caso contrário ambos os argumentos --log e --server devem estar presentes.'
			].join('\n'));
			process.exit(code);
		};
	
		let processCmdLine = function() {
			let i = 2;
			let args = new Map();
			while (i < process.argv.length) {
				if (process.argv[i].startsWith('--help') || process.argv[i].startsWith('-h')) usage(0);
				if (process.argv[i].startsWith('--')) {
					let arg = process.argv[i].split('=');
					if (arg.length === 2) args.set(arg[0], new String(arg[1]));
				}
				i++;
			}
		
			let config, logOptions, serverOptions;
			try {
				if (args.has('--config')) {
					let cfgPath = path.resolve(args.get('--config').valueOf());
					config = Config.load(cfgPath);
				}
				else if (args.has('--log') && args.has('--server')) {
					let logArg = args.get('--log');
					Config.validate(logArg);
					logOptions = JSON.parse(logArg);
					if (!logOptions.fname.includes('-n')) throw new Error('Opção fname de log inválida');
					if (logOptions.level < LogLevel.DEBUG || logOptions.level > LogLevel.ERROR) throw new Error('Opção level de log inválida');
				
					let svrArg = args.get('--server');
					Config.validate(svrArg);
					serverOptions = JSON.parse(svrArg);
					if (serverOptions.port < 1024 || serverOptions.port > 65535) throw new Error ('Opção port de serviço inválida');
					if (!Array.isArray(serverOptions.trustedOrigins.origins)) throw new Error('Opção trustedOrigins.origins de serviço inválida');
					let i = 0;
					while (i < serverOptions.trustedOrigins.origins.length) {
						if (typeof serverOptions.trustedOrigins.origins[i].origin !== 'string') throw new Error('Opção trustedOrigins.origins.origin de serviço inválida');
						if (typeof serverOptions.trustedOrigins.origins[i].id !== 'string') throw new Error(')pção trustedOrigins.origins.id de serviço inválida');
						i++;
					}
				}
				else usage(1);
			}
			catch (e) {
				console.log(sprintf('Ocorreu o seguinte Erro ao processar os argumentos: %s. Assumindo valores padrão', e.message));
				logOptions = {
					path: path.join(__dirname, 'runtime'),
					fname: 'xapiripe-n.log',
					maxSize: 2048,
					rotate: 5,
					level: 1
				};
				serverOptions = {
					port: 9171,
					maxAge: 1800,
					trustedOrigins: {
						warning: true,
						origins: []
					}
				};
			}
		
			let name = args.has('--service') ? args.get('--service') : 'Hekura';
			let ret = new Map();
			ret.set('name', name);
			if (config) ret.set('config', config);
			if (logOptions)	ret.set('log', logOptions);
			if (serverOptions) ret.set('server', serverOptions);
			return ret;
		};


		/**
		 * Evento emitido caso um Ctrl + C seja teclado. Sinal utilizado somente no caso do serviço ser
		 * executado pelo Node.js e não pela aplicação Electron.
		 * Finaliza o serviço.
		 */
		process.on('SIGINT', async () => {
			console.log('Finalizando o serviço...');
			quitService();
		});

		/**
		 * Finalização do processo. Libera recursos alocados
		 */
		process.on('exit', (code) => {
			Logger.releaseLogger();
		});

		/**
		 * Evento emitido quando uma mensagem do processo principal é recebida, a saber:
		 * STOP: finalizar o serviço
		 * WARN: resposta ao alerta emitido ao usuário (ver approvalCallback)
		 */
		process.on('message', (message) => {
			if (message.signal === Message.STOP) {
				quitService();
			}
			else if (message.signal === Message.WARN) {
				logger.debug(sprintf('Mensagem recebida:\n%s', JSON.stringify(message, null, 2)));
				let promise = messages.get(message.msgId);
				if (promise) {
					promise.resolve(message.response);
					messages.delete(message.msgId);
				}
				else logger.error(sprintf('Mensagem desconhecida recebida:\n%s', JSON.stringify(message, null, 2)));
			}
			else if (message.signal === Message.LOG) { logger.warn(message.message); }
			else if (message.signal === Message.INFO) { logger.info(message.info); }
			else logger.error(sprintf('Mensagem desconhecida recebida:\n%s', JSON.stringify(message, null, 2)));
		});


		let args = processCmdLine(), logOpt,  svrOpt;
		if (args.has('config')) {
			let cfg = args.get('config');
			logOpt = cfg.logOptions;
			svrOpt = cfg.serverOptions;
		}
		else {
			logOpt = args.get('log');
			svrOpt = args.get('server');
		}
		
		let origins = [];
		svrOpt.trustedOrigins.origins.forEach((element) => {
			origins.push(element.origin);
		});
	
		Logger.logConfig(logOpt);
		logger = Logger.getLogger(args.get('name') + ' Service App');
		service = new HTTPServer(svrOpt.port, svrOpt.maxAge,  new CORSBlockade(origins), approvalCallback, args.get('name'));
	
		require('readline').createInterface({
			input: process.stdin,
			output: process.stdout
		}).on('SIGINT', () => {
			process.emit('SIGINT');
		});
	
		await service.start();
		logger.info(sprintf('Log do serviço iniciado com as seguinte opções:\n%s\nServiço iniciado com as seguintes opções:\n%s', JSON.stringify(logOpt, null, 2), JSON.stringify(svrOpt, null, 2)));
	}
	catch (err) {
		let code = err.toString();
		let msg;
		if (code === ServiceError.HTTP_PORT_ALREADY_USED.toString()) msg = 'A porta de serviço já está em uso';
		else msg = err.toString();
		alert('Ocorreu um erro fatal na operação do serviço, a saber: '.concat(msg, '. O aplicativo precisa ser encerrado.'));
	}
}());
