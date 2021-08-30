/*!
 * Copyright (c) 2015-present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and limitations under the License.
 */

const spawn = require('cross-spawn-with-kill');
const waitOn = require('wait-on');
// eslint-disable-next-line node/no-unpublished-require
require('../../env'); // set environment variables

// 1. start the sample's web server
const server = spawn('yarn', [
  '--cwd',
  '../app',
  'start'
], { stdio: 'inherit' });

waitOn({
  resources: [
    `http-get://localhost:8080`
  ]
}).then(() => {
  // 2. run webdriver based on if sauce is needed or not
  // TODO: support saucelab and cucumber
  const protractorConfig = 'protractor.conf.js';

  let opts = process.argv.slice(2); // pass extra arguments through
  const runner = spawn('yarn', [
    'protractor',
    protractorConfig
  ].concat(opts), { stdio: 'inherit' });

  let returnCode = 1;
  runner.on('exit', function (code) {
    console.log('Test runner exited with code: ', code);
    returnCode = code;
    server.kill();
  });
  runner.on('error', function (err) {
    server.kill();
    throw err;
  });
  server.on('exit', function(code) {
    console.log('Server exited with code: ', code);
    // eslint-disable-next-line no-process-exit
    process.exit(returnCode);
  });
  process.on('exit', function() {
    console.log('Process exited with code: ', returnCode);
  });
});
