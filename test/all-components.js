'use strict';


const { testHamahiri } = require('./hamahiri-test');
const { testAroari } = require('./aroari-test');
const { testWanhamou } = require('./wanhamou-test');
const { testHekura } = require('./hekura-test');
const { testLock } = require('./test-lock');
const { testOptions } = require('./test-options');

const components = [ testHamahiri, testAroari, testWanhamou, testHekura, testLock, testOptions ];

(function () {

	let i = 0;
	while (i < components.length) {
		components[i++]();
	}
	
}());
