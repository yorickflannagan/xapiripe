
/**
 * @file Módulo nativo Node.js para criar arquivo com lock exclusivo sob o Windows
 * @copyright Copyleft &copy; 2023 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const addon = require('./lock-native');
const path = require('path');
const fs = require('fs');

/**
 * Cria (ou abre, se existir) um arquivo de selo para acesso exclusivo
 */
class Lock {
	/**
	 * Cria uma nova instância do controle de acesso exclusivo
	 * @param { String } arg Diretório onde deve ser criado o arquivo de lock. Opcional. Default: diretório corrente
	 * @param { String } fname Nome do arquivo de lock. Opcional Default: xapiripe.lock~
	 */
	constructor(arg, fname) {
		let loc = __dirname;
		if (arg) loc = arg;
		let location;
		try {
			location = path.resolve(loc);
			let stats = fs.lstatSync(location, { throwIfNoEntry : false });
			if (!stats || !stats.isDirectory()) throw new Error();
		}
		catch (e) { throw new Error('First argument must be an existing directory'); }
		let file = 'xapiripe.lock~';
		if (fname) file = fname;
		this.__lockfile = path.resolve(location, file);
		this.__fd = 0;
		this.__locker = new addon.Lock();
	}
	/**
	 * Cria um novo arquivo de selo para acesso exclusivo. 
	 * @throws { Error } Dispara exceções caso o arquivo de selo já tenha sido criado pela instância corrente
	 * ou caso não seja possível obter um bloqueio para acesso exclusivo.
	 */
	createLock() {
		if (this.__fd != 0) throw new Error('Stamp file already created');
		this.__fd = fs.openSync(this.__lockfile, 'a+');
		if (!this.__locker.flock(this.__fd)) {
			fs.closeSync(this.__fd);
			throw new Error('Cannot create and lock stamp file');
		}
	}
	/**
	 * Libera o arquivo de selo para acesso exclusivo.
	 * @throws { Error } Dispara uma exceção caso o método createLock() não tenha sido executado previamente
	 * ou se não for possível liberar o lock anterior.
	 */
	releaseLock() {
		if (this.__fd == 0) throw new Error('Stamp file must be locked first');
		if (!this.__locker.funlock(this.__fd)) throw new Error('Cannot release lock stamp file');
		fs.closeSync(this.__fd);
		fs.unlinkSync(this.__lockfile);
		this.__fd = 0;
	}
}

module.exports = { Lock };
