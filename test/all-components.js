'use strict';


const { testHamahiri } = require('./hamahiri-test');
const { testAroari } = require('./aroari-test');
const { testWanhamou } = require('./wanhamou-test');
const { testHekura } = require('./hekura-test');

const components = [ testHamahiri, testAroari, testWanhamou, testHekura ];

(function () {

	let i = 0;
	while (i < components.length) {
		components[i++]();
	}
	
}());
