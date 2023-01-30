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
 * service.js - Background Hekura aservice
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

const path = require('path');
const fs = require('fs');
const Hekura = require('hekura');
const Wanhamou = require('wanhamou');
const sprintf = Wanhamou.sprintf;
const LogLevel = Wanhamou.LogLevel;
const Logger = Wanhamou.Logger;

let service = null;
process.on('SIGINT', async () => {
	console.log('Finalizando o serviço...');
	if (service) await service.stop();
	process.exit();
});
process.on('message', async (message) => {
	if (message.signal === 'stop-service') {
		if (service) await service.stop();
		process.exit();
	}
});

function approvalCallback(operationId, referer, value) {
	// TODO: Implement a callback to Signthing
	return true;
}

function usage(code) {
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
}

function processCmdLine() {
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
			if (!fs.existsSync(cfgPath)) throw new Error('Argumento --config deve apontar para um arquivo existente');
			let val = fs.readFileSync(cfgPath, { encoding: 'utf-8' });
			config = JSON.parse(val);
		}
		else if (args.has('--log') && args.has('--server')) {
			logOptions = JSON.parse(args.get('--log'));
			if (typeof logOptions.path !== 'string' || !fs.existsSync(logOptions.path)) throw new Error('Opção path de log inválida');
			if (typeof logOptions.fname !== 'string' || !logOptions.fname.includes('-n')) throw new Error('Opção fname de log inválida');
			if (typeof logOptions.maxSize !== 'number') throw new Error('Opção maxSize de log inválida');
			if (typeof logOptions.rotate !== 'number') throw new Error('Opção rotate de log inválida');
			if (typeof logOptions.level !== 'number' || logOptions.level < LogLevel.DEBUG || logOptions.level > LogLevel.ERROR) throw new Error('Opção level de log inválida');
		
			serverOptions = JSON.parse(args.get('--server'));
			if (typeof serverOptions.port !== 'number' || serverOptions.port < 1024 || serverOptions.port > 65535) throw new Error ('Opção port de serviço inválida');
			if (typeof serverOptions.maxAge !== 'number') throw new Error('Opção maxAge de serviço inválida');
			if (typeof serverOptions.trustedOrigins !== 'object') throw new Error('Opção trustedOrigins de serviço inválida');
			if (typeof serverOptions.trustedOrigins.warning !== 'boolean') throw new Error('Opção trustedOrigins.warning de serviço inválida');
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
			path: path.resolve(__dirname),
			fname: 'xapiripe-n.log',
			maxSize: 2048,
			rotate: 5,
			level: 1
		}
		serverOptions = {
			port: 9171,
			maxAge: 1800,
			trustedOrigins: {
				warning: true,
				origins: []
			}
		}
	}

	let ret = new Map();
	if (config) ret.set('config', config);
	if (logOptions)	ret.set('log', logOptions);
	if (serverOptions) ret.set('server', serverOptions);
	return ret;
}

async function main() {
	let args = processCmdLine();
	let logOpt;
	let svrOpt;
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
	let serverOptions = {
		port: svrOpt.port,
		maxAge: svrOpt.maxAge,
		cors: new Hekura.CORSBlockade(origins),
		callback: approvalCallback
	}

	Logger.logConfig(logOpt);
	service = new Hekura.HTTPServer(serverOptions);

	require('readline').createInterface({
		input: process.stdin,
		output: process.stdout
	}).on('SIGINT', () => {
		process.emit('SIGINT');
	});

	await service.start();
	Logger.getLogger('Signthing service').info(
		sprintf(
			'Log do serviço iniciado com as seguinte opções:\n%s\nServiço Hekura iniciado com as seguintes opções:\n%s',
			JSON.stringify(logOpt, null, 2),
			JSON.stringify(svrOpt, null, 2)
		)
	);
	Logger.releaseLogger();
}	main();
