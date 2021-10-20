/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 * 		diego.sohsten@gmail.com
 *
 * Signithing - desktop application UI
 * See https://bitbucket.org/yorick-flannagan/signithing/src/master/
 * sign.js - sign.html behaviour
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

let sigWizLoaded = false;
let sigWizCurrentStep = 0;	// current wizard step
const FIRST_STEP = 1;
const SECOND_STEP = 2;
const LAST_STEP = 3;
const steps = new Map();
steps.set(1, 'step-1');
steps.set(2, 'step-2');
steps.set(3, 'step-3');

/**
 * Navigate to specified wizard step
 * @param { number } number: step number
 * @returns void
 */
function sigWizSetStep(number)
{
	if (number < FIRST_STEP || number > LAST_STEP) return;
	let lastStep = sigWizCurrentStep;
	sigWizCurrentStep = number;

	const iframe = document.getElementById('sign-div');
	const prev = iframe.contentWindow.document.getElementById('prev');
	if (sigWizCurrentStep == FIRST_STEP)
	{
		prev.dataset.role = 'close';
		prev.value = 'Cancel';
	}
	else
	{
		prev.dataset.role = 'previous';
		prev.value = 'Previous';
	}

	const next = iframe.contentWindow.document.getElementById('next');
	if (sigWizCurrentStep == LAST_STEP)
	{
		next.dataset.role = 'close';
		next.value = "Finish";
	}
	else
	{
		next.dataset.role = 'next';
		next.value = 'Next';
	}

	if (lastStep > 0) iframe.contentWindow.document.getElementById(steps.get(lastStep)).style = 'display: none';
	iframe.contentWindow.document.getElementById(steps.get(sigWizCurrentStep)).style = 'display: block';
}

function sigWizClose()
{
	const iframe = document.getElementById('sign-div');
	document.getElementById('sign-div').style = 'display: none';
	iframe.contentWindow.document.getElementById('source').value = '';
	iframe.contentWindow.document.getElementById('target').value = '';
	iframe.style = 'display: none';
	window.retreatCall();

}

document.addEventListener('sign-wizard-open', () => {
	try
	{
		// UI elements
		const iframe = document.getElementById('sign-div');
		const certList = iframe.contentWindow.document.getElementById('certificate');
		const algorithm = iframe.contentWindow.document.getElementById('algorithm');
		const format = iframe.contentWindow.document.getElementById('format');
		const remember = iframe.contentWindow.document.getElementById('remember');
		const srcButton = iframe.contentWindow.document.getElementById('btn-source');
		const tgtButton = iframe.contentWindow.document.getElementById('btn-target');
		const prevButton = iframe.contentWindow.document.getElementById('prev');
		const nextButton = iframe.contentWindow.document.getElementById('next');
		const srcText = iframe.contentWindow.document.getElementById('source');
		const tgtText = iframe.contentWindow.document.getElementById('target');
		const attach = iframe.contentWindow.document.getElementById('attach');
		const srcFile = iframe.contentWindow.document.getElementById('src-file');
		const tgtFile = iframe.contentWindow.document.getElementById('tgt-file');

		// Load available certificates
		const certs = window.getCertificates();
		certList.innerHTML = '';
		certs.forEach((value) => {
			let option = iframe.contentWindow.document.createElement('option');
			option.text = value;
			certList.add(option);
		});

		// Recall stored options
		const cfg = window.getConfig();
		certList.selectedIndex = cfg.signatureOptions.certificate;
		algorithm.selectedIndex = cfg.signatureOptions.algorithm;
		format.selectedIndex = cfg.signatureOptions.format;
		remember.checked = (cfg.signatureOptions.step > FIRST_STEP);
		attach.checked = cfg.attach;
		sigWizSetStep(cfg.signatureOptions.step);

		// Show open file dialog
		if (!sigWizLoaded)
		srcButton.addEventListener('click', () => {
			let choice = window.openFile({
				title: 'Select a file to sign',
				defaultPath: cfg.lastFolder,
				properties: [ 'openFile' ]
			});
			if (choice !== undefined)
			{
				srcText.value = choice[0];
				tgtText.value = window.changeExt(choice[0], '.p7b');
				cfg.lastFolder = window.parentFolder(choice[0]);
			}
		});

		// Show save file dialog
		if (!sigWizLoaded)
		tgtButton.addEventListener('click', () => {
			let choice = window.saveFile( { title: 'Select a destination folder', defaultPath: cfg.lastFolder });
			if (choice !== undefined) tgtText.value = choice;
		});

		// Previous button
		if (!sigWizLoaded)
		prevButton.addEventListener('click', () => {
			if (prevButton.dataset.role == 'close') sigWizClose();
			else sigWizSetStep(sigWizCurrentStep - 1);
		});

		// Next button
		if (!sigWizLoaded)
		nextButton.addEventListener('click', () => {
			switch (sigWizCurrentStep)
			{
			case FIRST_STEP:
				if (certList.selectedIndex == -1 || algorithm.selectedIndex == -1 || format.selectedIndex == -1)
				{
					window.showMessage({ message: 'You must select all available options', title: 'Document signature', tipe: 'warning' });
					return;
				}
				break;
			case SECOND_STEP:
				if (!window.fileExists(srcText.value) || window.fileExists(tgtText.value))
				{
					window.showMessage({ message: 'You must select all available options', title: 'Document signature', tipe: 'warning' });
					return;
				}
				srcFile.innerHTML = srcText.value;
				tgtFile.innerHTML = tgtText.value;
				break;
			case LAST_STEP:
				if (remember.checked)
				{
					cfg.signatureOptions.certificate = certList.selectedIndex;
					cfg.signatureOptions.algorithm = algorithm.selectedIndex;
					cfg.signatureOptions.format = format.selectedIndex;
					cfg.signatureOptions.step = 2;
					cfg.attach = attach.checked;
				}
				cfg.lastFolder = window.parentFolder(srcText.value);
				window.updateConfig(cfg);
				let ret = window.sign({
					signingCert: certList.options[certList.selectedIndex].text,
					signingAlgorithm: algorithm.options[algorithm.selectedIndex].text,
					envelopeFormat: format.options[format.selectedIndex].text,
					saveChoices: remember.checked,
					signedContents: srcText.value,
					signedEnvelope: tgtText.value,
					attachContents: attach.checked
				});
				window.showMessage({
					message: ret.message,
					title: 'Document Signature',
					type: ret.success ? 'info' : 'error',
					detail: ret.detail
				});
				sigWizClose();
				return;
			}
			sigWizSetStep(sigWizCurrentStep + 1);
		});
	}
	catch (err)
	{
		window.showMessage({
			message: err.message ? err.message : err,
			type: 'error',
			title: 'Error on loading page',
			detail: 'The application is not functioning properly'
		});
	}
	sigWizLoaded = true;
});
