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

import { Injectable, Injector, Inject } from '@angular/core';
import {
  CanActivate,
  CanActivateChild,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
  Router,
  NavigationStart, 
  Event,
  CanLoad,
  Route,
  Data
} from '@angular/router';
import { filter } from 'rxjs/operators';

import { OktaAuth, AuthState, TokenParams } from '@okta/okta-auth-js';
import { OktaAuthConfigService } from './services/auth-config.serice';
import { AuthRequiredFunction, OKTA_AUTH } from './models/okta.config';

@Injectable()
export class OktaAuthGuard implements CanActivate, CanActivateChild, CanLoad {
  private state: RouterStateSnapshot;
  private routeData: Data;
  private onAuthRequired?: AuthRequiredFunction;

  constructor(
    @Inject(OKTA_AUTH) private oktaAuth: OktaAuth, 
    private injector: Injector,
    private configService: OktaAuthConfigService
  ) {
    const config = this.configService.getConfig();
    if (!config) {
      throw new Error('Okta config is not provided');
    }
    this.onAuthRequired = config.onAuthRequired;

    // Unsubscribe updateAuthStateListener when route change
    const router = injector.get(Router);
    router.events.pipe(
      filter((e: Event) => e instanceof NavigationStart && this.state && this.state.url !== e.url)
    ).subscribe(() => {
      this.oktaAuth.authStateManager.unsubscribe(this.updateAuthStateListener);
    });
  }

  async canLoad(route: Route): Promise<boolean> {
    this.onAuthRequired = route.data?.onAuthRequired || this.onAuthRequired;

    const isAuthenticated = await this.isAuthenticated(route.data);
    if (isAuthenticated) {
      return true;
    }

    const router = this.injector.get(Router);
    const nav = router.getCurrentNavigation();
    const originalUri = nav ? nav.extractedUrl.toString() : undefined;
    await this.handleLogin(originalUri, route.data);

    return false;
  }

  /**
   * Gateway for protected route. Returns true if there is a valid idToken,
   * otherwise it will cache the route and start the login flow.
   * @param route
   * @param state
   */
  async canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Promise<boolean> {
    // Track states for current route
    this.state = state;
    this.routeData = route.data;
    this.onAuthRequired = route.data && route.data.onAuthRequired || this.onAuthRequired;

    // Protect the route after accessing
    this.oktaAuth.authStateManager.subscribe(this.updateAuthStateListener);
    const isAuthenticated = await this.isAuthenticated(route.data);
    if (isAuthenticated) {
      return true;
    }

    await this.handleLogin(state.url, route.data);

    return false;
  }

  async canActivateChild(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Promise<boolean> {
    return this.canActivate(route, state);
  }

  private async isAuthenticated(routeData?: Data, authState?: AuthState | null) {
    const isAuthenticated = authState ? authState?.isAuthenticated : await this.oktaAuth.isAuthenticated();
    let res = isAuthenticated;
    if (routeData?.okta?.acrValues) {
      if (!authState) {
        authState = this.oktaAuth.authStateManager.getAuthState();
      }
      res = authState?.idToken?.claims.acr === routeData?.okta?.acrValues;
    }
    return res;
  }

  private async handleLogin(originalUri?: string, routeData?: Data): Promise<void> {
    // Store the current path
    if (originalUri) {
      this.oktaAuth.setOriginalUri(originalUri);
    }

    const options: TokenParams = {};
    if (routeData?.okta?.acrValues) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore Supports auth-js >= 7.1.0
      options.acrValues = routeData.okta.acrValues;
    }

    if (this.onAuthRequired) {
      this.onAuthRequired(this.oktaAuth, this.injector, options);
    } else {
      this.oktaAuth.signInWithRedirect(options);
    }
  }

  private updateAuthStateListener = async (authState: AuthState) => {
    const isAuthenticated = await this.isAuthenticated(this.routeData, authState);
    if (!isAuthenticated) {
      this.handleLogin(this.state.url, this.routeData);
    }
  };

}
