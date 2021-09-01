/*
 * Copyright (c) 2017-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import { Component, OnInit, Optional, Injector, Inject } from '@angular/core';
import { OktaAuth } from '@okta/okta-auth-js';
import { OKTA_CONFIG, OktaConfig } from '../models/okta.config';

@Component({
  template: `<div>{{error}}</div>`
})
export class OktaCallbackComponent implements OnInit {
  error: string;

  constructor(
    @Inject(OKTA_CONFIG) private config: OktaConfig,
    private oktaAuth: OktaAuth,
    @Optional() private injector?: Injector
  ) {}

  async ngOnInit(): Promise<void> {
    try {
      // Parse code or tokens from the URL, store tokens in the TokenManager, and redirect back to the originalUri
      await this.oktaAuth.handleLoginRedirect();
    } catch (e) {
      // Callback from social IDP. Show custom login page to continue.
      if (this.oktaAuth.isInteractionRequiredError(e) && this.injector) {
        const { onAuthResume, onAuthRequired } = this.config;
        const callbackFn = onAuthResume || onAuthRequired;
        if (callbackFn) {
          callbackFn(this.oktaAuth, this.injector);
          return;
        }
      }
      this.error = e.toString();
    }
  }
}
