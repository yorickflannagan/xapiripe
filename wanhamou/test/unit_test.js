/**
 * @file Testes de unidade do dispositivo simplificado de log
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

 'use strict';

const path = require('path');
const Wanhamou = require(path.join(__dirname, '..'));
const fs = require('fs');
const wanhamou = require('../src/wanhamou');
const LOG = process.stdout;

class LogTest
{
	constructor() {
		this.tests = 0;
	}
	defaultLogTestCase() {
		LOG.write('Testing default logger initialization...');
		let logger = Wanhamou.Logger.getLogger('LogTest');
		let stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (!stats.isFile()) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Log file was not created');
		}
		let file = path.join(__dirname, '..', 'src', Wanhamou.Logger.cfgLogPattern.replace('-n', '-0'));
		if (!fs.existsSync(file)) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Log file not found in file system');
		}
		let size = stats.size;
		logger.debug('Esta mensagem não deve ser registrada');
		stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (stats.size > size) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Debug logged at info level');
		}
		logger.info('Mensagem de nível informativo');
		stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (stats.size == size) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Info message did not log at info level');
		}
		size = stats.size;
		logger.warn('Mensagem de alerta');
		stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (stats.size == size) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Warn message did not log at info leve');
		}
		size = stats.size;
		logger.error('Mensagem de erro');
		stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (stats.size == size) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Error message did not log at info leve');
		}
		Wanhamou.Logger.releaseLogger();
		this.tests++;
		LOG.write(' done!\n');
	}
	logRotationTestCase() {
		LOG.write('Testing log file rotation...');
		Wanhamou.Logger.logConfig({ maxSize: 1 });
		let logger = Wanhamou.Logger.getLogger('LogTest');
		for (let i = 0; i < 9; i++) logger.info('Mensagem feita para forçar o estouro do log');
		logger.info('Mensagem feita para forçar o estouro do log');
		let file = path.join(__dirname, '..', 'src', Wanhamou.Logger.cfgLogPattern.replace('-n', '-1'));
		if (!fs.existsSync(file)) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Rotated log file not found in the file system');
		}
		let stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (stats.size == 0) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('The new log file did not grow as expected');
		}
		Wanhamou.Logger.releaseLogger();
		this.tests++;
		LOG.write(' done!\n');
	}
	logTruncationTestCase() {
		LOG.write('Testing log file rotation and truncation...');
		Wanhamou.Logger.logConfig({ maxSize: 1 });
		let logger = Wanhamou.Logger.getLogger('LogTest');
		for (let i = 0; i < 11; i++) logger.info('Mensagem feita para forçar o estouro do log');
		let file = path.join(__dirname, '..', 'src', Wanhamou.Logger.cfgLogPattern.replace('-n', '-2'));
		if (!fs.existsSync(file)) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('Rotated log file not found in the file system');
		}
		for (let i = 0; i < 10; i++) logger.info('Mensagem feita para forçar o estouro do log');
		logger.error('Mensagem que deve ser gravada no primeiro arquivo de log');
		let stats = fs.fstatSync(Wanhamou.Logger.globalFD);
		if (stats.size > 1024) {
			Wanhamou.Logger.releaseLogger();
			throw new Error('The oldest log file was not truncated as expected');
		}
		Wanhamou.Logger.releaseLogger();
		this.tests++;
		LOG.write(' done!\n');
	}
	logReleaseTestCase() {
		LOG.write('Testing log file descriptor release...');
		let logger = Wanhamou.Logger.getLogger('LogTest');
		logger.info('Registro de uma instância');
		let log = Wanhamou.Logger.getLogger('AnotherLog');
		log.info('Registro de outra instância');
		Wanhamou.Logger.releaseLogger();
		if (Wanhamou.Logger.globalFD == 0) throw new Error('The log file descriptor was released too soon');
		Wanhamou.Logger.releaseLogger();
		if (Wanhamou.Logger.globalFD != 0) throw new Error('The log file descriptor was not released as expected');
		this.tests++;
		LOG.write(' done!\n');
	}
}

function main() {

	console.log('Log device test battery');
	let test = new LogTest();
	test.defaultLogTestCase();
	test.logRotationTestCase();
	test.logTruncationTestCase();
	test.logReleaseTestCase();
	LOG.write(test.tests.toString());
	LOG.write(' test cases performed.\n');

	// Clean-up
	let file = path.join(__dirname, '..', 'src', Wanhamou.Logger.cfgLogPattern.replace('-n', '-0'));
	fs.unlinkSync(file);
	file = path.join(__dirname, '..', 'src', Wanhamou.Logger.cfgLogPattern.replace('-n', '-1'));
	fs.unlinkSync(file);
	file = path.join(__dirname, '..', 'src', Wanhamou.Logger.cfgLogPattern.replace('-n', '-2'));
	fs.unlinkSync(file);

}	main();