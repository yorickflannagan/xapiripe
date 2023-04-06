const { Lock } = require('../components/lock');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { Worker } = require('worker_threads');
const yargs = require('yargs');
const argv = yargs(process.argv).argv;
const LOG = process.stdout;

LOG.write('Testing Lock module...');
assert(Lock, "The expected module is undefined");
LOG.write(' done!\n');
let tests = 1;
console.log(__dirname);
console.log(__filename);

function testHappyPath() {
	LOG.write('Testing happy path to current folder...');
	let locker = new Lock();
	let lockfile = path.resolve(__dirname, '..', 'components', 'xapiripe.lock~');
	assert.strictEqual(lockfile, locker.__lockfile, 'Stamp file must point to script current folder');
	locker.createLock();
	assert.ok(locker.__fd != 0, 'File descriptor must be initialized');
	assert.ok(fs.existsSync(lockfile), 'Exclusive stamp file must be created at script current folder');
	locker.releaseLock();
	assert.ok(locker.__fd == 0, 'File descriptor must be available to new lock after released');
	assert.ok(!fs.existsSync(lockfile), 'Stamp file must not remain after released');
	LOG.write(' done!\n');
	tests++;
}
function testAnotherFolder() {
	LOG.write('Testing lock in another folder');
	let locker = new Lock(__dirname);
	let lockfile = path.resolve(__dirname, 'xapiripe.lock~');
	assert.strictEqual(lockfile, locker.__lockfile, 'Stamp file must point to project test folder');
	locker.createLock();
	assert.ok(locker.__fd != 0, 'File descriptor must be initialized');
	assert.ok(fs.existsSync(lockfile), 'Exclusive stamp file must be created at project test folder');
	locker.releaseLock();
	assert.ok(locker.__fd == 0, 'File descriptor must be available to new lock after released');
	assert.ok(!fs.existsSync(lockfile), 'Stamp file must not remain after released');
	LOG.write(' done!\n');
	tests++;
}
function testRecicleLocker() {
	LOG.write('Testing recicle locker...');
	let locker = new Lock();
	let lockfile = path.resolve(__dirname, '..', 'components', 'xapiripe.lock~');
	assert.strictEqual(lockfile, locker.__lockfile, 'Stamp file must point to current folder');
	locker.createLock();
	assert.ok(locker.__fd != 0, 'File descriptor must be initialized');
	assert.ok(fs.existsSync(lockfile), 'Exclusive stamp file must be created at current folder');
	locker.releaseLock();
	assert.ok(locker.__fd == 0, 'File descriptor must be available to new lock after released');
	assert.ok(!fs.existsSync(lockfile), 'Stamp file must not remain after released');
	locker.createLock();
	assert.ok(locker.__fd != 0, 'File descriptor must be initialized');
	assert.ok(fs.existsSync(lockfile), 'Exclusive stamp file must be created at current folder');
	locker.releaseLock();
	assert.ok(locker.__fd == 0, 'File descriptor must be available to new lock after released');
	assert.ok(!fs.existsSync(lockfile), 'Stamp file must not remain after released');
	LOG.write(' done!\n');
	tests++;
}
function testNonExistentFolder() {
	LOG.write('Testing create lock in a non-existent folder...');
	assert.throws(() => { new Lock('./abc'); }, undefined, 'Cannot instantiate locker in a non-existing folder');
	LOG.write(' done!\n');
	tests++;
}
function testInvalidCalls() {
	LOG.write('Testing invalid calls to component...');
	let locker;
	assert.doesNotThrow(() => { locker = new Lock(); }, 'Unexpected error on object creation');
	assert.throws(() => { locker.releaseLock(); }, 'Lock must me created before released');
	assert.doesNotThrow(() => { locker.createLock(); }, 'Unexpected lock failure');
	assert.throws(() => { locker.createLock(); }, 'Cannot lock an already locked stamp');
	assert.doesNotThrow(() => { locker.releaseLock(); }, 'Unexpected unlock failure');
	LOG.write(' done!\n');
	tests++;
}
function testAnotherInstanceLock() {
	LOG.write('Testing multiple locks...');
	let locker, anotherOne;
	assert.doesNotThrow(() => { locker = new Lock(); }, 'Unexpected error on object creation');
	assert.doesNotThrow(() => { locker.createLock(); }, 'Unexpected lock failure');
	assert.doesNotThrow(() => { anotherOne = new Lock(); }, 'Unexpected error on object creation');
	assert.throws(() => { anotherOne.createLock(); }, 'Cannot lock an already locked stamp');
	assert.doesNotThrow(() => { locker.releaseLock(); }, 'Unexpected unlock failure');
	LOG.write(' done!\n');
	tests++;
}

function testLock() {
	testHappyPath();
	testAnotherFolder();
	testRecicleLocker();
	testNonExistentFolder();
	testInvalidCalls();
	testAnotherInstanceLock();
	LOG.write(tests.toString() + ' tests done!\n');
}

if (argv.check) testLock();
module.exports = { testLock };
